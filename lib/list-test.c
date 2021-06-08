#include "gs-common.h"
#include <gsocket/gsocket.h>
#include "gs-externs.h"

static void
output(GS_LIST *list)
{
	GS_LIST_ITEM *li = NULL;

	while (1)
	{
		li = GS_LIST_next(list, li);
		if (li == NULL)
			break;
		DEBUGF("add_id = %d, id = %"PRIu64"\n", li->add_id, li->id);
	}
}

static void
check_order(GS_LIST *list)
{
	// Check order is still ok
	int n = 0;
	GS_LIST_ITEM *li = NULL;
	GS_LIST_ITEM *next;
	while (1)
	{
		li = GS_LIST_next(list, li);
		if (li == NULL)
			break;

		next = (GS_LIST_ITEM *)li->next;
		if (next != NULL)
		{
			XASSERT(li->id <= next->id, "not in order %"PRIu64" <= %"PRIu64"\n", li->id, next->id);
			if (li->id == next->id)
			{
				XASSERT(li->add_id < next->add_id, "Wrong order\n");
			}
		}
		n++;
	}
}

int
main(int argc, char *argv[])
{
	GS_LIST list;

	GS_library_init(stderr, stderr, NULL);
	srand(time(NULL));

	GS_LIST_init(&list, 0);
	GS_LIST_ITEM *li = NULL;

	//Check that GS_LIST_next() is working
	int n = 0;
	while (1)
	{
		li = GS_LIST_next(&list, li);
		if (li == NULL)
			break;
		n += 1;
	}
	XASSERT(n == 0, "n is %d != 0\n", n);

	// Add entries with random id's.
	int max = 10000;
	n = 0;
	uint64_t id;
	int max_id = 20;
	while (n < max)
	{
		id = rand() % max_id;
		GS_LIST_add(&list, NULL, "dummy data", id);
		// Check order after every entry
		check_order(&list);

		n++;
	}
	int total = n;

	// output(&list);
	DEBUGF("Items in list: %d\n", list.n_items);

	// Delete / Add randomly until no items are left
	int chance;
	int pos;
	int del_count = 0;
	int add_count = 0;
	while (total > 0)
	{
		chance = 0;
		chance = rand() % 3; // 1/3 chance for GS_LIST_add()
		if (chance == 2)
		{
			id = rand() % max_id;
			GS_LIST_add(&list, NULL, "new dummy", id);
			total += 1;
			add_count += 1;
			check_order(&list);
			continue;
		}

		pos = rand() % total;
		li = GS_LIST_by_pos(&list, pos);
		XASSERT(li != NULL, "requested pos that doesnt exist (pos = %d, total = %d)\n", pos, total);

		GS_LIST_del(li);
		check_order(&list);
		total--;
		del_count += 1;
		check_order(&list);
	}

	XASSERT(del_count == add_count + max, "Oops. deleted = %d but total+add = %d\n", del_count, add_count + max);

	output(&list);
	DEBUGF("Randomly added while deleting at the same: %d\n", add_count);
	DEBUGF("Items in list: %d\n", list.n_items);

	DEBUGF("hello world\n");
	return 0;
}
