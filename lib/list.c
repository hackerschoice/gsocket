/*
 * Double Linked List
 */
 #include "gs-common.h"
 #include <gsocket/gsocket.h>
 #include "gs-externs.h"

#define GS_LIST_PREV(xitem)	((GS_LIST_ITEM *)xitem)->prev
#define GS_LIST_NEXT(xitem)	((GS_LIST_ITEM *)xitem)->next

int
GS_LIST_init(GS_LIST *gsl, int opt)
{
	memset(gsl, 0, sizeof *gsl);

	gsl->opt = opt;

	return 0;	
}


GS_LIST_ITEM *
GS_LIST_next(GS_LIST *gsl, GS_LIST_ITEM *li)
{
	if (li == NULL)
		return gsl->head;

	return li->next;
}

static void
gs_list_unlink(GS_LIST_ITEM *del_li)
{
	GS_LIST *gsl = del_li->gsl;

	if (del_li->prev == NULL)
		gsl->head = del_li->next;  // Might be NULL
	else
		GS_LIST_NEXT(del_li->prev) = del_li->next;

	if (del_li->next == NULL)
		gsl->tail = del_li->prev; // Might be NULL
	else
		GS_LIST_PREV(del_li->next) = del_li->prev;

	gsl->n_items -= 1;
}

static void
gs_list_link(GS_LIST_ITEM *src_li)
{
	GS_LIST *gsl = src_li->gsl;

	// First element
	if (gsl->head == NULL)
	{
		gsl->tail = src_li;
		gsl->head = src_li;
		src_li->next = NULL;
		src_li->prev = NULL;

		return;
	}

	// Start from tail to find insert location
	GS_LIST_ITEM *li = gsl->tail;
	// DEBUGF("Tail id == %llu\n", li->id);
	while (li != NULL)
	{
		if (li->id <= src_li->id)
			break;

		li = li->prev;
	}
	// DEBUGF("Add %llu below this one: %llu\n", id, li->id);

	// id is smallest (e.g. becoming head)
	if (li == NULL)
	{
		// DEBUGF("Becoming head\n");
		// li becoming the head
		src_li->next = gsl->head;
		src_li->prev = NULL;
		gsl->head->prev = src_li;
		gsl->head = src_li;

		return;
	}

	// Add below li
	src_li->next = li->next; // == NULL if tail
	src_li->prev = li;
	if (li->next != NULL) // Not the tail
		GS_LIST_PREV(li->next) = src_li;
	else
		gsl->tail = src_li; // next tail
	li->next = src_li;
}

void
GS_LIST_relink(GS_LIST_ITEM *li, uint64_t id)
{
	li->id = id;
	gs_list_unlink(li);
	gs_list_link(li);
}

/*
 * Add an item to the list. Sorted by id. Lowest at top.
 */
GS_LIST_ITEM *
GS_LIST_add(GS_LIST *gsl, GS_LIST_ITEM *src_li, void *data, uint64_t id)
{
	if (src_li == NULL)
	{
		src_li = calloc(1, sizeof *src_li);
		XASSERT(src_li != NULL, "calloc(): %s\n", strerror(errno));
		src_li->is_calloc = 1;
	} else {
		src_li->is_calloc = 0;
	}

	src_li->data = data;
	src_li->id = id;
	src_li->gsl = gsl;
	src_li->add_id = gsl->add_count;

	gsl->add_count += 1;
	gsl->n_items += 1;

	gs_list_link(src_li);

	// DEBUGF("tail id = %llu\n", gsl->tail->id);
	return src_li;
}

GS_LIST_ITEM *
GS_LIST_by_pos(GS_LIST *gsl, int pos)
{
	if (pos >= gsl->n_items)
		return NULL;

	int n = 0;
	GS_LIST_ITEM *li = NULL;
	while (1)
	{
		li = GS_LIST_next(gsl, li);
		if (li == NULL)
			break;
		if (n == pos)
			break;
		n += 1;
	}

	return li;
}

int
GS_LIST_del(GS_LIST_ITEM *del_li)
{
	if (del_li == NULL)
		return 0;
	gs_list_unlink(del_li);
	if (del_li->is_calloc)
		XFREE(del_li);

	return 0;
}

int
GS_LIST_del_all(GS_LIST *gsl, int deep)
{
	GS_LIST_ITEM *li;

	while (1)
	{
		li = GS_LIST_next(gsl, NULL);
		if (li == NULL)
			break;
		if (deep)
			XFREE(li->data);
		GS_LIST_del(li);
	}

	return 0;
}

