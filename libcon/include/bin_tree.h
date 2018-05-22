
typedef unsigned int tree_entry[9];

struct bin_tree {
	tree_entry			data;
	struct bin_tree		* right, *left;
};

typedef struct bin_tree node;

LIBC_API		int				C_API_FUNC bt_insert (node ** tree, tree_entry val);
LIBC_API		void			C_API_FUNC bt_deltree(node * tree);
LIBC_API		node *			C_API_FUNC bt_search (node * tree, tree_entry val);

