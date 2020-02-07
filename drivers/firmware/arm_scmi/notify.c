// SPDX-License-Identifier: GPL-2.0
/*
 * System Control and Management Interface (SCMI) Notification support
 *
 * Copyright (C) 2020 ARM Ltd.
 */
/**
 * DOC: Theory of operation
 *
 * SCMI Protocol specification allows the platform to signal events to
 * interested agents via notification messages: this is an implementation
 * of the dispatch and delivery of such notifications to the interested users
 * inside the Linux kernel.
 *
 * An SCMI Notification core instance is initialized for each active platform
 * instance identified by the means of the usual &struct scmi_handle.
 *
 * Each SCMI Protocol implementation, during its initialization, registers with
 * this core its set of supported events using scmi_register_protocol_events():
 * all the needed descriptors are stored in the &struct registered_protocols and
 * &struct registered_events arrays.
 *
 * Kernel users interested in some specific event can register their callbacks
 * providing the usual notifier_block descriptor, since this core implements
 * events' delivery using the standard Kernel notification chains machinery.
 *
 * Given the number of possible events defined by SCMI and the extensibility
 * of the SCMI Protocol itself, the underlying notification chains are created
 * and destroyed dynamically on demand depending on the number of users
 * effectively registered for an event, so that no support structures or chains
 * are allocated until at least one user has registered a notifier_block for
 * such event. Similarly, events' generation itself is enabled at the platform
 * level only after at least one user has registered, and it is shutdown after
 * the last user for that event has gone.
 *
 * All users provided callbacks and allocated notification-chains are stored in
 * the @registered_events_handlers hashtable. Callbacks' registration requests
 * for still to be registered events are instead kept in the dedicated common
 * hashtable @pending_events_handlers.
 *
 * An event is identified univocally by the tuple (proto_id, evt_id, src_id)
 * and is served by its own dedicated notification chain; information contained
 * in such tuples is used, in a few different ways, to generate the needed
 * hash-keys.
 *
 * Here proto_id and evt_id are simply the protocol_id and message_id numbers
 * as described in the SCMI Protocol specification, while src_id represents an
 * optional, protocol dependent, source identifier (like domain_id, perf_id
 * or sensor_id and so forth).
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/atomic.h>
#include <linux/bitfield.h>
#include <linux/bug.h>
#include <linux/compiler.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/hashtable.h>
#include <linux/kernel.h>
#include <linux/kfifo.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/refcount.h>
#include <linux/scmi_protocol.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "notify.h"

#define	SCMI_MAX_PROTO			256
#define	SCMI_ALL_SRC_IDS		0xffffUL
/*
 * Builds an unsigned 32bit key from the given input tuple to be used
 * as a key in hashtables.
 */
#define MAKE_HASH_KEY(p, e, s)			\
	((u32)(((p) << 24) | ((e) << 16) | ((s) & SCMI_ALL_SRC_IDS)))

#define MAKE_ALL_SRCS_KEY(p, e)			\
	MAKE_HASH_KEY((p), (e), SCMI_ALL_SRC_IDS)

/*
 * Assumes that the stored obj includes its own hash-key in a field named 'key':
 * with this simplification this macro can be equally used for all the objects'
 * types hashed by this implementation.
 *
 * @__ht: The hashtable name
 * @__obj: A pointer to the object type to be retrieved from the hashtable;
 *	   it will be used as a cursor while scanning the hastable and it will
 *	   be possibly left as NULL when @__k is not found
 * @__k: The key to search for
 */
#define KEY_FIND(__ht, __obj, __k)				\
({								\
	hash_for_each_possible((__ht), (__obj), hash, (__k))	\
		if (likely((__obj)->key == (__k)))		\
			break;					\
	__obj;							\
})

#define PROTO_ID_MASK			GENMASK(31, 24)
#define EVT_ID_MASK			GENMASK(23, 16)
#define SRC_ID_MASK			GENMASK(15, 0)
#define KEY_XTRACT_PROTO_ID(key)	FIELD_GET(PROTO_ID_MASK, (key))
#define KEY_XTRACT_EVT_ID(key)		FIELD_GET(EVT_ID_MASK, (key))
#define KEY_XTRACT_SRC_ID(key)		FIELD_GET(SRC_ID_MASK, (key))

/*
 * A set of macros used to access safely @registered_protocols and
 * @registered_events arrays; these are fixed in size and each entry is possibly
 * populated at protocols' registration time and then only read but NEVER
 * modified or removed.
 */
#define SCMI_GET_PROTO(__ni, __pid)					\
({									\
	struct scmi_registered_protocol_events_desc *__pd = NULL;	\
									\
	if ((__ni) && (__pid) < SCMI_MAX_PROTO)				\
		__pd = READ_ONCE((__ni)->registered_protocols[(__pid)]);\
	__pd;								\
})

#define SCMI_GET_REVT_FROM_PD(__pd, __eid)				\
({									\
	struct scmi_registered_event *__revt = NULL;			\
									\
	if ((__pd) && (__eid) < (__pd)->num_events)			\
		__revt = READ_ONCE((__pd)->registered_events[(__eid)]);	\
	__revt;								\
})

#define SCMI_GET_REVT(__ni, __pid, __eid)				\
({									\
	struct scmi_registered_event *__revt = NULL;			\
	struct scmi_registered_protocol_events_desc *__pd = NULL;	\
									\
	__pd = SCMI_GET_PROTO((__ni), (__pid));				\
	__revt = SCMI_GET_REVT_FROM_PD(__pd, (__eid));			\
	__revt;								\
})

/* A couple of utility macros to limit cruft when calling protocols' helpers */
#define REVT_NOTIFY_ENABLE(revt, eid, sid)				       \
	((revt)->proto->ops->set_notify_enabled((revt)->proto->ni->handle,     \
						(eid), (sid), true))
#define REVT_NOTIFY_DISABLE(revt, eid, sid)				       \
	((revt)->proto->ops->set_notify_enabled((revt)->proto->ni->handle,     \
						(eid), (sid), false))

struct scmi_registered_protocol_events_desc;

/**
 * struct scmi_notify_instance  - Represents an instance of the notification
 * core
 * @gid: GroupID used for devres
 * @handle: A reference to the platform instance
 * @initialized: A flag that indicates if the core resources have been allocated
 *		 and protocols are allowed to register their supported events
 * @enabled: A flag to indicate events can be enabled and start flowing
 * @init_work: A work item to perform final initializations of pending handlers
 * @pending_mtx: A mutex to protect @pending_events_handlers
 * @registered_protocols: A statically allocated array containing pointers to
 *			  all the registered protocol-level specific information
 *			  related to events' handling
 * @pending_events_handlers: An hashtable containing all pending events'
 *			     handlers descriptors
 *
 * Each platform instance, represented by a handle, has its own instance of
 * the notification subsystem represented by this structure.
 */
struct scmi_notify_instance {
	void						*gid;
	struct scmi_handle				*handle;
	atomic_t					initialized;
	atomic_t					enabled;

	struct work_struct				init_work;

	struct mutex					pending_mtx;
	struct scmi_registered_protocol_events_desc	**registered_protocols;
	DECLARE_HASHTABLE(pending_events_handlers, 8);
};

/**
 * struct events_queue  - Describes a queue and its associated worker
 * @sz: Size in bytes of the related kfifo
 * @kfifo: A dedicated Kernel kfifo descriptor
 *
 * Each protocol has its own dedicated events_queue descriptor.
 */
struct events_queue {
	size_t				sz;
	struct kfifo			kfifo;
};

/**
 * struct scmi_event_header  - A utility header
 * @timestamp: The timestamp, in nanoseconds (boottime), which was associated
 *	       to this event as soon as it entered the SCMI RX ISR
 * @evt_id: Event ID (corresponds to the Event MsgID for this Protocol)
 * @payld_sz: Effective size of the embedded message payload which follows
 * @payld: A reference to the embedded event payload
 *
 * This header is prepended to each received event message payload before
 * queueing it on the related &struct events_queue.
 */
struct scmi_event_header {
	u64	timestamp;
	u8	evt_id;
	size_t	payld_sz;
	u8	payld[];
} __packed;

struct scmi_registered_event;

/**
 * struct scmi_registered_protocol_events_desc  - Protocol Specific information
 * @id: Protocol ID
 * @ops: Protocol specific and event-related operations
 * @equeue: The embedded per-protocol events_queue
 * @ni: A reference to the initialized instance descriptor
 * @eh: A reference to pre-allocated buffer to be used as a scratch area by the
 *	deferred worker when fetching data from the kfifo
 * @eh_sz: Size of the pre-allocated buffer @eh
 * @in_flight: A reference to an in flight &struct scmi_registered_event
 * @num_events: Number of events in @registered_events
 * @registered_events: A dynamically allocated array holding all the registered
 *		       events' descriptors, whose fixed-size is determined at
 *		       compile time.
 * @registered_mtx: A mutex to protect @registered_events_handlers
 * @registered_events_handlers: An hashtable containing all events' handlers
 *				descriptors registered for this protocol
 *
 * All protocols that register at least one event have their protocol-specific
 * information stored here, together with the embedded allocated events_queue.
 * These descriptors are stored in the @registered_protocols array at protocol
 * registration time.
 *
 * Once these descriptors are successfully registered, they are NEVER again
 * removed or modified since protocols do not unregister ever, so that, once
 * we safely grab a NON-NULL reference from the array we can keep it and use it.
 */
struct scmi_registered_protocol_events_desc {
	u8					id;
	const struct scmi_protocol_event_ops	*ops;
	struct events_queue			equeue;
	struct scmi_notify_instance		*ni;
	struct scmi_event_header		*eh;
	size_t					eh_sz;
	void					*in_flight;
	int					num_events;
	struct scmi_registered_event		**registered_events;
	struct mutex				registered_mtx;
	DECLARE_HASHTABLE(registered_events_handlers, 8);
};

/**
 * struct scmi_registered_event  - Event Specific Information
 * @proto: A reference to the associated protocol descriptor
 * @evt: A reference to the associated event descriptor (as provided at
 *       registration time)
 * @report: A pre-allocated buffer used by the deferred worker to fill a
 *	    customized event report
 * @num_sources: The number of possible sources for this event as stated at
 *		 events' registration time
 * @sources: A reference to a dynamically allocated array used to refcount the
 *	     events' enable requests for all the existing sources
 * @sources_mtx: A mutex to serialize the access to @sources
 *
 * All registered events are represented by one of these structures that are
 * stored in the @registered_events array at protocol registration time.
 *
 * Once these descriptors are successfully registered, they are NEVER again
 * removed or modified since protocols do not unregister ever, so that once we
 * safely grab a NON-NULL reference from the table we can keep it and use it.
 */
struct scmi_registered_event {
	struct scmi_registered_protocol_events_desc	*proto;
	const struct scmi_event				*evt;
	void						*report;
	u32						num_sources;
	refcount_t					*sources;
	struct mutex					sources_mtx;
};

/**
 * struct scmi_event_handler  - Event handler information
 * @key: The used hashkey
 * @users: A reference count for number of active users for this handler
 * @r_evt: A reference to the associated registered event; when this is NULL
 *	   this handler is pending, which means that identifies a set of
 *	   callbacks intended to be attached to an event which is still not
 *	   known nor registered by any protocol at that point in time
 * @chain: The notification chain dedicated to this specific event tuple
 * @hash: The hlist_node used for collision handling
 * @enabled: A boolean which records if event's generation has been already
 *	     enabled for this handler as a whole
 *
 * This structure collects all the information needed to process a received
 * event identified by the tuple (proto_id, evt_id, src_id).
 * These descriptors are stored in a per-protocol @registered_events_handlers
 * table using as a key a value derived from that tuple.
 */
struct scmi_event_handler {
	u32				key;
	refcount_t			users;
	struct scmi_registered_event	*r_evt;
	struct blocking_notifier_head	chain;
	struct hlist_node		hash;
	bool				enabled;
};

#define IS_HNDL_PENDING(hndl)	((hndl)->r_evt == NULL)

static void scmi_put_handler_unlocked(struct scmi_notify_instance *ni,
				      struct scmi_event_handler *hndl);

/**
 * scmi_kfifo_free()  - Devres action helper to free the kfifo
 * @kfifo: The kfifo to free
 */
static void scmi_kfifo_free(void *kfifo)
{
	kfifo_free((struct kfifo *)kfifo);
}

/**
 * scmi_initialize_events_queue()  - Allocate/Initialize a kfifo buffer
 * @ni: A reference to the notification instance to use
 * @equeue: The events_queue to initialize
 * @sz: Size of the kfifo buffer to allocate
 *
 * Allocate a buffer for the kfifo and initialize it.
 *
 * Return: 0 on Success
 */
static int scmi_initialize_events_queue(struct scmi_notify_instance *ni,
					struct events_queue *equeue, size_t sz)
{
	if (kfifo_alloc(&equeue->kfifo, sz, GFP_KERNEL))
		return -ENOMEM;
	/* Size could have been roundup to power-of-two */
	equeue->sz = kfifo_size(&equeue->kfifo);

	return devm_add_action_or_reset(ni->handle->dev, scmi_kfifo_free,
					&equeue->kfifo);
}

/**
 * scmi_allocate_registered_protocol_desc()  - Allocate a registered protocol
 * events' descriptor
 * @ni: A reference to the &struct scmi_notify_instance notification instance
 *	to use
 * @proto_id: Protocol ID
 * @queue_sz: Size of the associated queue to allocate
 * @eh_sz: Size of the event header scratch area to pre-allocate
 * @num_events: Number of events to support (size of @registered_events)
 * @ops: Pointer to a struct holding references to protocol specific helpers
 *	 needed during events handling
 *
 * It is supposed to be called only once for each protocol at protocol
 * initialization time, so it warns if the requested protocol is found already
 * registered.
 *
 * Return: The allocated and registered descriptor on Success
 */
static struct scmi_registered_protocol_events_desc *
scmi_allocate_registered_protocol_desc(struct scmi_notify_instance *ni,
				       u8 proto_id, size_t queue_sz,
				       size_t eh_sz, int num_events,
				const struct scmi_protocol_event_ops *ops)
{
	int ret;
	struct scmi_registered_protocol_events_desc *pd;

	/* Ensure protocols are up to date */
	smp_rmb();
	if (ni->registered_protocols[proto_id]) {
		WARN_ON(1);
		return ERR_PTR(-EINVAL);
	}

	pd = devm_kzalloc(ni->handle->dev, sizeof(*pd), GFP_KERNEL);
	if (!pd)
		return ERR_PTR(-ENOMEM);
	pd->id = proto_id;
	pd->ops = ops;
	pd->ni = ni;

	ret = scmi_initialize_events_queue(ni, &pd->equeue, queue_sz);
	if (ret)
		return ERR_PTR(ret);

	pd->eh = devm_kzalloc(ni->handle->dev, eh_sz, GFP_KERNEL);
	if (!pd->eh)
		return ERR_PTR(-ENOMEM);
	pd->eh_sz = eh_sz;

	pd->registered_events = devm_kcalloc(ni->handle->dev, num_events,
					     sizeof(char *), GFP_KERNEL);
	if (!pd->registered_events)
		return ERR_PTR(-ENOMEM);
	pd->num_events = num_events;

	/* Initialize per protocol handlers table */
	mutex_init(&pd->registered_mtx);
	hash_init(pd->registered_events_handlers);

	return pd;
}

/**
 * scmi_register_protocol_events()  - Register Protocol Events with the core
 * @handle: The handle identifying the platform instance against which the
 *	    the protocol's events are registered
 * @proto_id: Protocol ID
 * @queue_sz: Size in bytes of the associated queue to be allocated
 * @ops: Protocol specific event-related operations
 * @evt: Event descriptor array
 * @num_events: Number of events in @evt array
 * @num_sources: Number of possible sources for this protocol on this
 *		 platform.
 *
 * Used by SCMI Protocols initialization code to register with the notification
 * core the list of supported events and their descriptors: takes care to
 * pre-allocate and store all needed descriptors, scratch buffers and event
 * queues.
 *
 * Return: 0 on Success
 */
int scmi_register_protocol_events(const struct scmi_handle *handle,
				  u8 proto_id, size_t queue_sz,
				  const struct scmi_protocol_event_ops *ops,
				  const struct scmi_event *evt, int num_events,
				  int num_sources)
{
	int i;
	size_t payld_sz = 0;
	struct scmi_registered_protocol_events_desc *pd;
	struct scmi_notify_instance *ni = handle->notify_priv;

	if (!ops || !evt || proto_id >= SCMI_MAX_PROTO)
		return -EINVAL;

	/* Ensure atomic value is updated */
	smp_mb__before_atomic();
	if (unlikely(!ni || !atomic_read(&ni->initialized)))
		return -EAGAIN;

	/* Attach to the notification main devres group */
	if (!devres_open_group(ni->handle->dev, ni->gid, GFP_KERNEL))
		return -ENOMEM;

	for (i = 0; i < num_events; i++)
		payld_sz = max_t(size_t, payld_sz, evt[i].max_payld_sz);
	pd = scmi_allocate_registered_protocol_desc(ni, proto_id, queue_sz,
				    sizeof(struct scmi_event_header) + payld_sz,
						    num_events, ops);
	if (IS_ERR(pd))
		goto err;

	for (i = 0; i < num_events; i++, evt++) {
		struct scmi_registered_event *r_evt;

		r_evt = devm_kzalloc(ni->handle->dev, sizeof(*r_evt),
				     GFP_KERNEL);
		if (!r_evt)
			goto err;
		r_evt->proto = pd;
		r_evt->evt = evt;

		r_evt->sources = devm_kcalloc(ni->handle->dev, num_sources,
					      sizeof(refcount_t), GFP_KERNEL);
		if (!r_evt->sources)
			goto err;
		r_evt->num_sources = num_sources;
		mutex_init(&r_evt->sources_mtx);

		r_evt->report = devm_kzalloc(ni->handle->dev,
					     evt->max_report_sz, GFP_KERNEL);
		if (!r_evt->report)
			goto err;

		pd->registered_events[i] = r_evt;
		/* Ensure events are updated */
		smp_wmb();
		pr_info("SCMI Notifications: registered event - %X\n",
			MAKE_ALL_SRCS_KEY(r_evt->proto->id, r_evt->evt->id));
	}

	/* Register protocol and events...it will never be removed */
	ni->registered_protocols[proto_id] = pd;
	/* Ensure protocols are updated */
	smp_wmb();

	devres_close_group(ni->handle->dev, ni->gid);

	/*
	 * Finalize any pending events' handler which could have been waiting
	 * for this protocol's events registration.
	 */
	schedule_work(&ni->init_work);

	return 0;

err:
	pr_warn("SCMI Notifications - Proto:%X - Registration Failed !\n",
		proto_id);
	/* A failing protocol registration does not trigger full failure */
	devres_close_group(ni->handle->dev, ni->gid);

	return -ENOMEM;
}

/**
 * scmi_allocate_event_handler()  - Allocate Event handler
 * @ni: A reference to the notification instance to use
 * @evt_key: 32bit key uniquely bind to the event identified by the tuple
 *	     (proto_id, evt_id, src_id)
 *
 * Allocate an event handler and related notification chain associated with
 * the provided event handler key.
 * Note that, at this point, a related registered_event is still to be
 * associated to this handler descriptor (hndl->r_evt == NULL), so the handler
 * is initialized as pending.
 *
 * Context: Assumes to be called with @pending_mtx already acquired.
 * Return: the freshly allocated structure on Success
 */
static struct scmi_event_handler *
scmi_allocate_event_handler(struct scmi_notify_instance *ni, u32 evt_key)
{
	struct scmi_event_handler *hndl;

	hndl = kzalloc(sizeof(*hndl), GFP_KERNEL);
	if (!hndl)
		return ERR_PTR(-ENOMEM);
	hndl->key = evt_key;
	BLOCKING_INIT_NOTIFIER_HEAD(&hndl->chain);
	refcount_set(&hndl->users, 1);
	/* New handlers are created pending */
	hash_add(ni->pending_events_handlers, &hndl->hash, hndl->key);

	return hndl;
}

/**
 * scmi_free_event_handler()  - Free the provided Event handler
 * @hndl: The event handler structure to free
 *
 * Context: Assumes to be called with proper locking acquired depending
 *	    on the situation.
 */
static void scmi_free_event_handler(struct scmi_event_handler *hndl)
{
	hash_del(&hndl->hash);
	kfree(hndl);
}

/**
 * scmi_bind_event_handler()  - Helper to attempt binding an handler to an event
 * @ni: A reference to the notification instance to use
 * @hndl: The event handler to bind
 *
 * If an associated registered event is found, move the handler from the pending
 * into the registered table.
 *
 * Context: Assumes to be called with @pending_mtx already acquired.
 * Return: True if bind was successful, False otherwise
 */
static inline bool scmi_bind_event_handler(struct scmi_notify_instance *ni,
					   struct scmi_event_handler *hndl)
{
	struct scmi_registered_event *r_evt;


	r_evt = SCMI_GET_REVT(ni, KEY_XTRACT_PROTO_ID(hndl->key),
			      KEY_XTRACT_EVT_ID(hndl->key));
	if (unlikely(!r_evt))
		return false;

	/* Remove from pending and insert into registered */
	hash_del(&hndl->hash);
	hndl->r_evt = r_evt;
	mutex_lock(&r_evt->proto->registered_mtx);
	hash_add(r_evt->proto->registered_events_handlers,
		 &hndl->hash, hndl->key);
	mutex_unlock(&r_evt->proto->registered_mtx);

	return true;
}

/**
 * scmi_valid_pending_handler()  - Helper to check pending status of handlers
 * @ni: A reference to the notification instance to use
 * @hndl: The event handler to check
 *
 * An handler is considered pending when its r_evt == NULL, because the related
 * event was still unknown at handler's registration time; anyway, since all
 * protocols register their supported events once for all at protocols'
 * initialization time, a pending handler cannot be considered valid anymore if
 * the underlying event (which it is waiting for), belongs to an already
 * initialized and registered protocol.
 *
 * Return: True if pending registration is still valid, False otherwise.
 */
static inline bool scmi_valid_pending_handler(struct scmi_notify_instance *ni,
					      struct scmi_event_handler *hndl)
{
	struct scmi_registered_protocol_events_desc *pd;

	if (unlikely(!IS_HNDL_PENDING(hndl)))
		return false;

	pd = SCMI_GET_PROTO(ni, KEY_XTRACT_PROTO_ID(hndl->key));
	if (pd)
		return false;

	return true;
}

/**
 * scmi_register_event_handler()  - Register whenever possible an Event handler
 * @ni: A reference to the notification instance to use
 * @hndl: The event handler to register
 *
 * At first try to bind an event handler to its associated event, then check if
 * it was at least a valid pending handler: if it was not bound nor valid return
 * false.
 *
 * Valid pending incomplete bindings will be periodically retried by a dedicated
 * worker which is kicked each time a new protocol completes its own
 * registration phase.
 *
 * Context: Assumes to be called with @pending_mtx acquired.
 * Return: True if a normal or a valid pending registration has been completed,
 *	   False otherwise
 */
static bool scmi_register_event_handler(struct scmi_notify_instance *ni,
					struct scmi_event_handler *hndl)
{
	bool ret;

	ret = scmi_bind_event_handler(ni, hndl);
	if (ret) {
		pr_info("SCMI Notifications: registered NEW handler - key:%X\n",
			hndl->key);
	} else {
		ret = scmi_valid_pending_handler(ni, hndl);
		if (ret)
			pr_info("SCMI Notifications: registered PENDING handler - key:%X\n",
				hndl->key);
	}

	return ret;
}

/**
 * __scmi_event_handler_get_ops()  - Utility to get or create an event handler
 * @ni: A reference to the notification instance to use
 * @evt_key: The event key to use
 * @create: A boolean flag to specify if a handler must be created when
 *	    not already existent
 *
 * Search for the desired handler matching the key in both the per-protocol
 * registered table and the common pending table:
 * * if found adjust users refcount
 * * if not found and @create is true, create and register the new handler:
 *   handler could end up being registered as pending if no matching event
 *   could be found.
 *
 * An handler is guaranteed to reside in one and only one of the tables at
 * any one time; to ensure this the whole search and create is performed
 * holding the @pending_mtx lock, with @registered_mtx additionally acquired
 * if needed.
 *
 * Note that when a nested acquisition of these mutexes is needed the locking
 * order is always (same as in @init_work):
 * 1. pending_mtx
 * 2. registered_mtx
 *
 * Events generation is NOT enabled right after creation within this routine
 * since at creation time we usually want to have all setup and ready before
 * events really start flowing.
 *
 * Return: A properly refcounted handler on Success, NULL on Failure
 */
static inline struct scmi_event_handler *
__scmi_event_handler_get_ops(struct scmi_notify_instance *ni,
			     u32 evt_key, bool create)
{
	struct scmi_registered_event *r_evt;
	struct scmi_event_handler *hndl = NULL;

	r_evt = SCMI_GET_REVT(ni, KEY_XTRACT_PROTO_ID(evt_key),
			      KEY_XTRACT_EVT_ID(evt_key));

	mutex_lock(&ni->pending_mtx);
	/* Search registered events at first ... if possible at all */
	if (likely(r_evt)) {
		mutex_lock(&r_evt->proto->registered_mtx);
		hndl = KEY_FIND(r_evt->proto->registered_events_handlers,
				hndl, evt_key);
		if (likely(hndl))
			refcount_inc(&hndl->users);
		mutex_unlock(&r_evt->proto->registered_mtx);
	}

	/* ...then amongst pending. */
	if (unlikely(!hndl)) {
		hndl = KEY_FIND(ni->pending_events_handlers, hndl, evt_key);
		if (likely(hndl))
			refcount_inc(&hndl->users);
	}

	/* Create if still not found and required */
	if (!hndl && create) {
		hndl = scmi_allocate_event_handler(ni, evt_key);
		if (!IS_ERR_OR_NULL(hndl)) {
			if (!scmi_register_event_handler(ni, hndl)) {
				pr_info("SCMI Notifications: purging UNKNOWN handler - key:%X\n",
					hndl->key);
				/* this hndl can be only a pending one */
				scmi_put_handler_unlocked(ni, hndl);
				hndl = NULL;
			}
		}
	}
	mutex_unlock(&ni->pending_mtx);

	return hndl;
}

static struct scmi_event_handler *
scmi_get_handler(struct scmi_notify_instance *ni, u32 evt_key)
{
	return __scmi_event_handler_get_ops(ni, evt_key, false);
}

static struct scmi_event_handler *
scmi_get_or_create_handler(struct scmi_notify_instance *ni, u32 evt_key)
{
	return __scmi_event_handler_get_ops(ni, evt_key, true);
}

/**
 * __scmi_enable_evt()  - Enable/disable events generation
 * @r_evt: The registered event to act upon
 * @src_id: The src_id to act upon
 * @enable: The action to perform: true->Enable, false->Disable
 *
 * Takes care of proper refcounting while performing enable/disable: handles
 * the special case of ALL sources requests by itself.
 *
 * Return: True when the required action has been successfully executed
 */
static inline bool __scmi_enable_evt(struct scmi_registered_event *r_evt,
				     u32 src_id, bool enable)
{
	int ret = 0;
	u32 num_sources;
	refcount_t *sid;

	if (src_id == SCMI_ALL_SRC_IDS) {
		src_id = 0;
		num_sources = r_evt->num_sources;
	} else if (src_id < r_evt->num_sources) {
		num_sources = 1;
	} else {
		return ret;
	}

	mutex_lock(&r_evt->sources_mtx);
	if (enable) {
		for (; num_sources; src_id++, num_sources--) {
			bool r;

			sid = &r_evt->sources[src_id];
			if (refcount_read(sid) == 0) {
				r = REVT_NOTIFY_ENABLE(r_evt,
						       r_evt->evt->id, src_id);
				if (r)
					refcount_set(sid, 1);
			} else {
				refcount_inc(sid);
				r = true;
			}
			ret += r;
		}
	} else {
		for (; num_sources; src_id++, num_sources--) {
			sid = &r_evt->sources[src_id];
			if (refcount_dec_and_test(sid))
				REVT_NOTIFY_DISABLE(r_evt,
						    r_evt->evt->id, src_id);
		}
		ret = 1;
	}
	mutex_unlock(&r_evt->sources_mtx);

	return ret;
}

static bool scmi_enable_events(struct scmi_event_handler *hndl)
{
	if (!hndl->enabled)
		hndl->enabled = __scmi_enable_evt(hndl->r_evt,
						  KEY_XTRACT_SRC_ID(hndl->key),
						  true);
	return hndl->enabled;
}

static bool scmi_disable_events(struct scmi_event_handler *hndl)
{
	if (hndl->enabled)
		hndl->enabled = !__scmi_enable_evt(hndl->r_evt,
						   KEY_XTRACT_SRC_ID(hndl->key),
						   false);
	return !hndl->enabled;
}

/**
 * scmi_put_handler_unlocked()  - Put an event handler
 * @ni: A reference to the notification instance to use
 * @hndl: The event handler to act upon
 *
 * After having got exclusive access to the registered handlers hashtable,
 * update the refcount and if @hndl is no more in use by anyone:
 * * ask for events' generation disabling
 * * unregister and free the handler itself
 *
 * Context: Assumes all the proper locking has been managed by the caller.
 */
static void
scmi_put_handler_unlocked(struct scmi_notify_instance *ni,
				struct scmi_event_handler *hndl)
{
	if (refcount_dec_and_test(&hndl->users)) {
		if (likely(!IS_HNDL_PENDING(hndl)))
			scmi_disable_events(hndl);
		scmi_free_event_handler(hndl);
	}
}

static void scmi_put_handler(struct scmi_notify_instance *ni,
			     struct scmi_event_handler *hndl)
{
	struct scmi_registered_event *r_evt = hndl->r_evt;

	mutex_lock(&ni->pending_mtx);
	if (r_evt)
		mutex_lock(&r_evt->proto->registered_mtx);

	scmi_put_handler_unlocked(ni, hndl);

	if (r_evt)
		mutex_unlock(&r_evt->proto->registered_mtx);
	mutex_unlock(&ni->pending_mtx);
}

/**
 * scmi_event_handler_enable_events()  - Enable events associated to an handler
 * @hndl: The Event handler to act upon
 *
 * Return: True on success
 */
static bool scmi_event_handler_enable_events(struct scmi_event_handler *hndl)
{
	if (!scmi_enable_events(hndl)) {
		pr_err("SCMI Notifications: Failed to ENABLE events for key:%X !\n",
		       hndl->key);
		return false;
	}

	return true;
}

/**
 * scmi_register_notifier()  - Register a notifier_block for an event
 * @handle: The handle identifying the platform instance against which the
 *	    callback is registered
 * @proto_id: Protocol ID
 * @evt_id: Event ID
 * @src_id: Source ID, when NULL register for events coming form ALL possible
 *	    sources
 * @nb: A standard notifier block to register for the specified event
 *
 * Generic helper to register a notifier_block against a protocol event.
 *
 * A notifier_block @nb will be registered for each distinct event identified
 * by the tuple (proto_id, evt_id, src_id) on a dedicated notification chain
 * so that:
 *
 *	(proto_X, evt_Y, src_Z) --> chain_X_Y_Z
 *
 * @src_id meaning is protocol specific and identifies the origin of the event
 * (like domain_id, sensor_id and so forth).
 *
 * @src_id can be NULL to signify that the caller is interested in receiving
 * notifications from ALL the available sources for that protocol OR simply that
 * the protocol does not support distinct sources.
 *
 * As soon as one user for the specified tuple appears, an handler is created,
 * and that specific event's generation is enabled at the platform level, unless
 * an associated registered event is found missing, meaning that the needed
 * protocol is still to be initialized and the handler has just been registered
 * as still pending.
 *
 * Return: Return 0 on Success
 */
static int scmi_register_notifier(const struct scmi_handle *handle,
				  u8 proto_id, u8 evt_id, u32 *src_id,
				  struct notifier_block *nb)
{
	int ret = 0;
	u32 evt_key;
	struct scmi_event_handler *hndl;
	struct scmi_notify_instance *ni = handle->notify_priv;

	if (unlikely(!ni || !atomic_read(&ni->initialized)))
		return 0;

	evt_key = MAKE_HASH_KEY(proto_id, evt_id,
				src_id ? *src_id : SCMI_ALL_SRC_IDS);
	hndl = scmi_get_or_create_handler(ni, evt_key);
	if (IS_ERR_OR_NULL(hndl))
		return PTR_ERR(hndl);

	blocking_notifier_chain_register(&hndl->chain, nb);

	/* Enable events for not pending handlers */
	if (likely(!IS_HNDL_PENDING(hndl))) {
		if (!scmi_event_handler_enable_events(hndl)) {
			scmi_put_handler(ni, hndl);
			ret = -EINVAL;
		}
	}

	return ret;
}

/**
 * scmi_unregister_notifier()  - Unregister a notifier_block for an event
 * @handle: The handle identifying the platform instance against which the
 *	    callback is unregistered
 * @proto_id: Protocol ID
 * @evt_id: Event ID
 * @src_id: Source ID
 * @nb: The notifier_block to unregister
 *
 * Takes care to unregister the provided @nb from the notification chain
 * associated to the specified event and, if there are no more users for the
 * event handler, frees also the associated event handler structures.
 * (this could possibly cause disabling of event's generation at platform level)
 *
 * Return: 0 on Success
 */
static int scmi_unregister_notifier(const struct scmi_handle *handle,
				    u8 proto_id, u8 evt_id, u32 *src_id,
				    struct notifier_block *nb)
{
	u32 evt_key;
	struct scmi_event_handler *hndl;
	struct scmi_notify_instance *ni = handle->notify_priv;

	if (unlikely(!ni || !atomic_read(&ni->initialized)))
		return 0;

	evt_key = MAKE_HASH_KEY(proto_id, evt_id,
				src_id ? *src_id : SCMI_ALL_SRC_IDS);
	hndl = scmi_get_handler(ni, evt_key);
	if (IS_ERR_OR_NULL(hndl))
		return -EINVAL;

	blocking_notifier_chain_unregister(&hndl->chain, nb);
	scmi_put_handler(ni, hndl);

	/*
	 * Free the handler (and stop events) if this happens to be the last
	 * known user callback for this handler; a possible concurrently ongoing
	 * run of @scmi_lookup_and_call_event_chain will cause this to happen
	 * in that context safely instead.
	 */
	scmi_put_handler(ni, hndl);

	return 0;
}

/**
 * scmi_protocols_late_init()  - Worker for late initialization
 * @work: The work item to use associated to the proper SCMI instance
 *
 * This kicks in whenever a new protocol has completed its own registration via
 * scmi_register_protocol_events(): it is in charge of scanning the table of
 * pending handlers (registered by users while the related protocol was still
 * not initialized) and finalizing their initialization whenever possible;
 * invalid pending handlers are purged at this point in time.
 */
static void scmi_protocols_late_init(struct work_struct *work)
{
	int bkt;
	struct scmi_event_handler *hndl;
	struct scmi_notify_instance *ni;
	struct hlist_node *tmp;

	ni = container_of(work, struct scmi_notify_instance, init_work);

	/* Ensure protocols and events are up to date */
	smp_rmb();

	mutex_lock(&ni->pending_mtx);
	hash_for_each_safe(ni->pending_events_handlers, bkt, tmp, hndl, hash) {
		bool ret;

		ret = scmi_bind_event_handler(ni, hndl);
		if (ret) {
			pr_info("SCMI Notifications: finalized PENDING handler - key:%X\n",
				hndl->key);
			ret = scmi_event_handler_enable_events(hndl);
		} else {
			ret = scmi_valid_pending_handler(ni, hndl);
		}
		if (!ret) {
			pr_info("SCMI Notifications: purging PENDING handler - key:%X\n",
				hndl->key);
			/* this hndl can be only a pending one */
			scmi_put_handler_unlocked(ni, hndl);
		}
	}
	mutex_unlock(&ni->pending_mtx);
}

/*
 * notify_ops are attached to the handle so that can be accessed
 * directly from an scmi_driver to register its own notifiers.
 */
static struct scmi_notify_ops notify_ops = {
	.register_event_notifier = scmi_register_notifier,
	.unregister_event_notifier = scmi_unregister_notifier,
};

/**
 * scmi_notification_init()  - Initializes Notification Core Support
 * @handle: The handle identifying the platform instance to initialize
 *
 * This function lays out all the basic resources needed by the notification
 * core instance identified by the provided handle: once done, all of the
 * SCMI Protocols can register their events with the core during their own
 * initializations.
 *
 * Note that failing to initialize the core notifications support does not
 * cause the whole SCMI Protocols stack to fail its initialization.
 *
 * SCMI Notification Initialization happens in 2 steps:
 * * initialization: basic common allocations (this function) -> @initialized
 * * registration: protocols asynchronously come into life and registers their
 *		   own supported list of events with the core; this causes
 *		   further per-protocol allocations
 *
 * Any user's callback registration attempt, referring a still not registered
 * event, will be registered as pending and finalized later (if possible)
 * by scmi_protocols_late_init() work.
 * This allows for lazy initialization of SCMI Protocols due to late (or
 * missing) SCMI drivers' modules loading.
 *
 * Return: 0 on Success
 */
int scmi_notification_init(struct scmi_handle *handle)
{
	void *gid;
	struct scmi_notify_instance *ni;

	gid = devres_open_group(handle->dev, NULL, GFP_KERNEL);
	if (!gid)
		return -ENOMEM;

	ni = devm_kzalloc(handle->dev, sizeof(*ni), GFP_KERNEL);
	if (!ni)
		goto err;

	ni->gid = gid;
	ni->handle = handle;

	ni->registered_protocols = devm_kcalloc(handle->dev, SCMI_MAX_PROTO,
						sizeof(char *), GFP_KERNEL);
	if (!ni->registered_protocols)
		goto err;

	mutex_init(&ni->pending_mtx);
	hash_init(ni->pending_events_handlers);

	INIT_WORK(&ni->init_work, scmi_protocols_late_init);

	handle->notify_priv = ni;
	handle->notify_ops = &notify_ops;

	atomic_set(&ni->initialized, 1);
	atomic_set(&ni->enabled, 1);
	/* Ensure atomic values are updated */
	smp_mb__after_atomic();

	pr_info("SCMI Notifications Core Initialized.\n");

	devres_close_group(handle->dev, ni->gid);

	return 0;

err:
	pr_warn("SCMI Notifications - Initialization Failed.\n");
	devres_release_group(handle->dev, NULL);
	return -ENOMEM;
}

/**
 * scmi_notification_exit()  - Shutdown and clean Notification core
 * @handle: The handle identifying the platform instance to shutdown
 */
void scmi_notification_exit(struct scmi_handle *handle)
{
	struct scmi_notify_instance *ni = handle->notify_priv;

	if (unlikely(!ni || !atomic_read(&ni->initialized)))
		return;

	atomic_set(&ni->enabled, 0);
	/* Ensure atomic values are updated */
	smp_mb__after_atomic();

	devres_release_group(ni->handle->dev, ni->gid);
}
