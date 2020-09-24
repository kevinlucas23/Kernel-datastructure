/*
 *- Linked list.
 *- Hash table.
 *- Red black tree.
 *- Radix tree.
 *- XArray.
 *
 */


// libraries below from the linux.
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/hashtable.h>
#include <linux/rbtree.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

static char *int_str;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kevin");
MODULE_DESCRIPTION("LKP Project 2");

module_param(int_str, charp, S_IRUSR | S_IRGRP | S_IROTH);

MODULE_PARM_DESC(int_str, "A comma-separated list of integers");

// to count the number of entries inserted in the data structure
static int count = 0, gone = 0;

// Proc file system entry
static struct proc_dir_entry *proj2_d;

// create Linked list.
static LIST_HEAD(mylist);

struct list_entry {
	int val;
	struct list_head list;
};

// create Hash table.
static DEFINE_HASHTABLE(myhash, 4);

struct hash_entry{
	int val;
	struct hlist_node hash;
};

// create Red black tree.
struct rb_root redblack_tree = RB_ROOT;

struct redblack_entry{
	int val;
	struct rb_node node;
};

// create radix tree.
static RADIX_TREE(radix_tree, GFP_KERNEL);

struct radix_entry{
	int val;
};

// create xarray
static DEFINE_XARRAY(xarray_tree);

struct xarray_entry{
	int val;
};

void my_insert(struct rb_root *root, struct redblack_entry *data){
	struct rb_node **new = &(root->rb_node), *parent;

	while(*new){
		struct redblack_entry *node = rb_entry(parent, struct redblack_entry, node);
		parent = *new;
		if(node->val > data->val){
			new = &(*new)->rb_left;
		}
		else {
			new = &(*new)->rb_right;
		}
	}
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, &redblack_tree);
}

// store the value from each entry.
static int store_value(int val) {
	struct list_entry *temp_list = kmalloc(sizeof(*temp_list), GFP_KERNEL);
	struct hash_entry *temp_hash = kmalloc(sizeof(*temp_hash), GFP_KERNEL);
	struct redblack_entry *temp_redblack = kmalloc(sizeof(*temp_redblack), GFP_KERNEL);
	struct radix_entry *temp_radix = kmalloc(sizeof(*temp_radix), GFP_KERNEL);
	struct xarray_entry *temp_xarray = kmalloc(sizeof(*temp_xarray), GFP_KERNEL);
	static int position = 0;

	if(!temp_list || !temp_hash || !temp_redblack || !temp_radix || !temp_xarray){
		return -ENOMEM;
	}
	else{
		temp_list->val = val;
		temp_hash->val = val;
		temp_redblack->val = val;
		temp_radix->val = val;
		temp_xarray->val = val;
		count++;
	}

	// list tree
	list_add_tail(&temp_list->list, &mylist);
	// hash
	hash_add(myhash, &temp_hash->hash, temp_hash->val);
	// red black tree
	my_insert(&redblack_tree, temp_redblack);
	// radix tree
	radix_tree_insert(&radix_tree, position, temp_radix);
	// xarray
	xa_store(&xarray_tree, position, temp_xarray, GFP_KERNEL);
	position++;
  printk(KERN_INFO "%i", position);
	return 0;
}

static void all_(int number[], int size, char every[], int conf){
	int i = 0, j = 0, q = 1024, z = 0;
  char* link = NULL;
	size_t n = size;
  if(conf = 1){
    link = (char* ) "Linked list:";
    printf(KERN_CONT "Linked list:");
    while((every[gone++]=*link) != ':' && gone < (q - 1)){
      ++link;
    }
    link = NULL;
  }
  if(conf = 2){
    link = (char* ) "Hash table:";
    printf(KERN_CONT "Hash table:");
    while((every[gone++]=*link) != ':' && gone < (q - 1)){
      ++link;
    }
    link = NULL;
  }
  if(conf = 3){
    link = (char* ) "Red-black tree:";
    printf(KERN_CONT "Red-black tree:");
    while((every[gone++]=*link) != ':' && gone < (q - 1)){
      ++link;
    }
    link = NULL;
  }
  if(conf = 4){
    link = (char* ) "Radix tree:";
    printf(KERN_CONT "Radix tree:");
    while((every[gone++]=*link) != ':' && gone < (q - 1)){
      ++link;
    }
    link = NULL;
  }
  if(conf = 5){
    link = (char* ) "XArray:";
    printf(KERN_CONT "XArray:");
    while((every[gone++]=*link) != ':' && gone < (q - 1)){
      ++link;
    }
    link = NULL;
  }
  while(gone + 3 < (q - 1)){
    if(j == 3){
      z += sprintf(&every[gone], ",");
      printk(KERN_CONT ",");
      j = 0;
    }
    else{
      if(i == n) break;
      z += sprintf(&every[gone], " %i", number[i]);
      printk(KERN_CONT " %i", number[i]);
      i++;
      j = 3;
    }
  }
  every[gone++] = '\n';
  printk(KERN_CONT "\n");
	// for(i = 0; i < (n - 1); ++i){
	// 	printk(KERN_CONT "%i,", number[i]);
	// }
	// printk(KERN_CONT " %i\n", number[n-1]);
}

static void test_all(char numero[]){
  struct list_entry *temp_list;
	struct hash_entry *temp_hash;
	struct rb_node *temp_redblack;
	struct radix_entry *temp_radix;
	struct xarray_entry *temp_xarray;
	int number[count];
	int j = 0, tor = 0;

	// "Elements in the linked list below"
	list_for_each_entry(temp_list, &mylist, list){
		number[tor] = temp_list->val;
		tor++;
	}
	all_(number, count, numero, 1);

	tor = 0;
	// "Elements in the hash list below"
	hash_for_each(myhash, j, temp_hash, hash){
		number[tor] = temp_hash->val;
		tor++;
	}
  all_(number, count, numero, 2);

	tor = 0;
	// "Elements in the red black tree below"
	for(temp_redblack = rb_first(&redblack_tree); temp_redblack; temp_redblack = rb_next(temp_redblack)){
		struct redblack_entry *tmp = rb_entry(temp_redblack, struct redblack_entry, node);
		number[tor] = tmp->val;
		tor++;
	}
  all_(number, count, numero, 3);

	tor = 0;
	// "Elements in the radix tree below";
	j =0;
	temp_radix = radix_tree_lookup(&radix_tree, j++);
	while(temp_radix){
		number[tor] = temp_radix->val;
		tor++;
		temp_radix = radix_tree_lookup(&radix_tree, j++);
		if(j > count) break;
	}
  all_(number, count, numero, 4);

	tor = 0;
	// "Elements in the xarray below";
	j =0;
	temp_xarray = xa_load(&xarray_tree, j++);
	while(temp_xarray){
		number[tor] = temp_xarray->val;
		tor++;
		temp_xarray = xa_load(&xarray_tree, j++);
		if(j > count) break;
	}
  all_(number, count, numero, 5);
  return;
}

ssize_t p2_read(struct file *filep, char __user *buf, size_t len, loff_t *off){
  char bufl[1024];
  int k = 0;
  if((*off) > 0) return 0;
  test_all(bufl);
  k = gone;
  if(copy_to_user(buf,bufl,k) > 0) return -EFAULT;
  (*off) += k;
  return k
}

static void destroy_all(void)
{
	int k = 0;
	struct list_entry *cursor = NULL, *temp = NULL;
	struct hash_entry *temp_h = NULL;
	struct redblack_entry *temp_re = NULL;
	struct rb_node *node_1 = NULL;
	struct radix_entry *temp_r;
	struct xarray_entry *temp_x = NULL;

	// "Destroying the linked list"
	list_for_each_entry_safe(cursor, temp, &mylist, list){
		list_del(&cursor->list);
		kfree(cursor);
	}

	// "Destroying the hash tree"
	hash_for_each(myhash, k, temp_h, hash){
		hash_del(&temp_h->hash);
		kfree(temp_h);
	}

	// "Destroying the red black tree"
	for(node_1 = rb_first(&redblack_tree); node_1; node_1 = rb_next(node_1)){
		temp_re = rb_entry(node_1, struct redblack_entry, node);
		rb_erase(node_1, &redblack_tree);
		kfree(node_1);
	}

	// "Destroying the rabix tree"
	k = 0;
	do{
		temp_r = radix_tree_delete(&radix_tree, k++);
		kfree(temp_r);
	}while(temp_r && k < count);

	// "Destroying the xarray";
	k = 0;
	do{
		temp_x = xa_erase(&xarray_tree, k++);
		kfree(temp_x);
	}while(temp_x && k < count);

}


static int parse_params(void)
{
	int val, err = 0;
	char *p, *orig, *params;

	params = kstrdup(int_str, GFP_KERNEL);
	if (!params)
		return -ENOMEM;
	orig = params;

	while ((p = strsep(&params, ",")) != NULL) {
		if (!*p)
			continue;

		err = kstrtoint(p, 0, &val);
		if (err)
			break;

		err = store_value(val);
		if (err)
			break;
	}

	kfree(orig);
	return err;
}

static void cleanup(void)
{
	printk(KERN_INFO "\nCleaning up...\n");
	destroy_all();
	//destroy_rb_tree_list_and_free();
}

const struct proc_ops fops = {
  .proc_read = p2_read,
};

static int __init proj2_init(void)
{
	int err = 0;

	proj2_d = proc_create("proj2", 0666, NULL, &fops);
  if (!proj2_d) {
		printk(KERN_INFO "eter, exiting\n");
		return -1;
	}
	if (!int_str) {
		printk(KERN_INFO "Missing \'int_str\' parameter, exiting\n");
		return -1;
	}

	err = parse_params();

	return err;
}


static void __exit proj2_exit(void)
{
	remove_proc_entry("proj2",NULL);
  cleanup();

	return;
}

module_init(proj2_init);
module_exit(proj2_exit);
