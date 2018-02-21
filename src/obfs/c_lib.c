/** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** **
 *  This file is part of clib library
 *  Copyright (C) 2011 Avinash Dongre ( dongre.avinash@gmail.com )
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** **/

#include "c_lib.h"

//==================== c_algorithms.c =============================================
#include "c_lib.h"
#include <stdlib.h>

void clib_for_each(struct clib_iterator *pIterator, void(*fn)(void*)) {
    struct clib_object *pElement;

    pElement = pIterator->get_next(pIterator);
    while (pElement) {
        void *value = pIterator->get_value(pElement);
        (fn)(value);
        free(value);
        pElement = pIterator->get_next(pIterator);
    }
}


//==================== c_array.c =============================================
#include "c_lib.h"
#include <string.h>
#include <stdio.h>

static struct clib_array * array_check_and_grow(struct clib_array* pArray) {
    if (pArray->no_of_elements >= pArray->no_max_elements) {
        pArray->no_max_elements = 2 * pArray->no_max_elements;
        pArray->pElements = (struct clib_object**) realloc(pArray->pElements,
            pArray->no_max_elements * sizeof(struct clib_object*));
    }
    return pArray;
}

struct clib_array * new_c_array(int array_size, clib_compare fn_c, clib_destroy fn_d) {
    struct clib_array* pArray = (struct clib_array*)malloc(sizeof(struct clib_array));
    if (!pArray) {
        return (struct clib_array*)0;
    }
    pArray->no_max_elements = array_size < 8 ? 8 : array_size;
    pArray->pElements = (struct clib_object**) malloc(pArray->no_max_elements * sizeof(struct clib_object*));
    if (!pArray->pElements) {
        free(pArray);
        return (struct clib_array*)0;
    }
    pArray->compare_fn = fn_c;
    pArray->destruct_fn = fn_d;
    pArray->no_of_elements = 0;

    return pArray;
}

static clib_error insert_c_array(struct clib_array* pArray, int index, void* elem, size_t elem_size) {
    clib_error rc = CLIB_ERROR_SUCCESS;
    struct clib_object* pObject = new_clib_object(elem, elem_size);
    if (!pObject) {
        return CLIB_ARRAY_INSERT_FAILED;
    }
    pArray->pElements[index] = pObject;
    pArray->no_of_elements++;
    return rc;
}

clib_error push_back_c_array(struct clib_array* pArray, void* elem, size_t elem_size) {
    clib_error rc = CLIB_ERROR_SUCCESS;

    if (!pArray) {
        return CLIB_ARRAY_NOT_INITIALIZED;
    }
    array_check_and_grow(pArray);

    rc = insert_c_array(pArray, pArray->no_of_elements, elem, elem_size);

    return rc;
}

clib_error element_at_c_array(struct clib_array* pArray, int index, void** elem) {
    clib_error rc = CLIB_ERROR_SUCCESS;

    if (!pArray) {
        return CLIB_ARRAY_NOT_INITIALIZED;
    }
    if (index < 0 || index > pArray->no_max_elements) {
        return CLIB_ARRAY_INDEX_OUT_OF_BOUND;
    }
    get_raw_clib_object(pArray->pElements[index], elem);
    return rc;
}

int size_c_array(struct clib_array* pArray) {
    if (pArray == (struct clib_array*)0) {
        return 0;
    }
    return pArray->no_of_elements - 1;
}

int capacity_c_array(struct clib_array* pArray) {
    if (pArray == (struct clib_array*)0) {
        return 0;
    }
    return pArray->no_max_elements;
}

clib_bool empty_c_array(struct clib_array* pArray) {
    if (pArray == (struct clib_array*)0) {
        return 0;
    }
    return pArray->no_of_elements == 0 ? clib_true : clib_false;
}

clib_error reserve_c_array(struct clib_array* pArray, int new_size) {
    if (pArray == (struct clib_array*)0) {
        return CLIB_ARRAY_NOT_INITIALIZED;
    }
    if (new_size <= pArray->no_max_elements) {
        return CLIB_ERROR_SUCCESS;
    }
    array_check_and_grow(pArray);
    return CLIB_ERROR_SUCCESS;
}

clib_error front_c_array(struct clib_array *pArray, void* elem) {
    return element_at_c_array(pArray, 0, elem);
}

clib_error back_c_array(struct clib_array *pArray, void *elem) {
    return element_at_c_array(pArray, pArray->no_of_elements - 1, elem);
}

clib_error insert_at_c_array(struct clib_array* pArray, int index, void* elem, size_t elem_size) {
    clib_error rc = CLIB_ERROR_SUCCESS;
    if (!pArray) {
        return CLIB_ARRAY_NOT_INITIALIZED;
    }
    if (index < 0 || index > pArray->no_max_elements) {
        return CLIB_ARRAY_INDEX_OUT_OF_BOUND;
    }
    array_check_and_grow(pArray);

    memmove(&(pArray->pElements[index + 1]),
        &pArray->pElements[index],
        (pArray->no_of_elements - index) * sizeof(struct clib_object*));

    rc = insert_c_array(pArray, index, elem, elem_size);

    return rc;
}

clib_error remove_from_c_array(struct clib_array *pArray, int index) {
    clib_error   rc = CLIB_ERROR_SUCCESS;

    if (!pArray) {
        return rc;
    }
    if (index < 0 || index > pArray->no_max_elements) {
        return CLIB_ARRAY_INDEX_OUT_OF_BOUND;
    }
    if (pArray->destruct_fn) {
        void* elem;
        if (CLIB_ERROR_SUCCESS == element_at_c_array(pArray, index, &elem)) {
            pArray->destruct_fn(elem);
            free(elem);
        }
    }
    delete_clib_object(pArray->pElements[index]);

    memmove(&(pArray->pElements[index]),
        &pArray->pElements[index + 1],
        (pArray->no_of_elements - index) * sizeof(struct clib_object*));
    pArray->no_of_elements--;

    return rc;
}

clib_error delete_c_array(struct clib_array *pArray) {
    clib_error rc = CLIB_ERROR_SUCCESS;
    int i = 0;

    if (pArray == (struct clib_array*)0) {
        return rc;
    }
    if (pArray->destruct_fn) {
        for (i = 0; i < pArray->no_of_elements; i++) {
            void* elem;
            if (CLIB_ERROR_SUCCESS == element_at_c_array(pArray, i, &elem)) {
                pArray->destruct_fn(elem);
                free(elem);
            }
        }
    }

    for (i = 0; i < pArray->no_of_elements; i++) {
        delete_clib_object(pArray->pElements[i]);
    }
    free(pArray->pElements);
    free(pArray);
    return rc;
}

static struct clib_object * get_next_c_array(struct clib_iterator *pIterator) {
    struct clib_array *pArray = (struct clib_array*)pIterator->pContainer;

    if (pIterator->pCurrent > size_c_array(pArray)) {
        return (struct clib_object*)0;
    }
    pIterator->pCurrentElement = pArray->pElements[pIterator->pCurrent++];
    return pIterator->pCurrentElement;
}

static void * get_value_c_array(void* pObject) {
    void* elem;
    get_raw_clib_object(pObject, &elem);
    return elem;
}

static void replace_value_c_array(struct clib_iterator *pIterator, void* elem, size_t elem_size) {
    struct clib_array*  pArray = (struct clib_array*)pIterator->pContainer;

    if (pArray->destruct_fn) {
        void* old_element;
        if (CLIB_ERROR_SUCCESS == get_raw_clib_object(pIterator->pCurrentElement, &old_element)) {
            pArray->destruct_fn(old_element);
            free(old_element);
        }
    }
    replace_raw_clib_object(pIterator->pCurrentElement, elem, elem_size);
}

struct clib_iterator * new_iterator_c_array(struct clib_array* pArray) {
    struct clib_iterator *itr = (struct clib_iterator*) calloc(1, sizeof(struct clib_iterator));
    itr->get_next = get_next_c_array;
    itr->get_value = get_value_c_array;
    itr->replace_value = replace_value_c_array;
    itr->pContainer = pArray;
    itr->pCurrent = 0;
    return itr;
}

void delete_iterator_c_array(struct clib_iterator* pItr) {
    free(pItr);
}


//==================== c_deque.c =============================================
#include "c_lib.h"
#include <string.h>

#define CLIB_DEQUE_INDEX(x)  ((char *)(pDeq)->pElements + (sizeof(struct clib_object) * (x)))

static clib_error insert_c_deque(struct clib_deque* pDeq, int index, void* elem, size_t elem_size) {
    clib_error rc = CLIB_ERROR_SUCCESS;
    struct clib_object* pObject = new_clib_object(elem, elem_size);
    if (!pObject) {
        return CLIB_ARRAY_INSERT_FAILED;
    }
    pDeq->pElements[index] = pObject;
    pDeq->no_of_elements++;
    return rc;
}

static struct clib_deque * grow_deque(struct clib_deque* pDeq) {
    pDeq->no_max_elements = pDeq->no_max_elements * 2;
    pDeq->pElements = (struct clib_object**) realloc(pDeq->pElements,
        pDeq->no_max_elements * sizeof(struct clib_object*));
    return pDeq;
}

struct clib_deque * new_c_deque(int deq_size, clib_compare fn_c, clib_destroy fn_d) {
    struct clib_deque* pDeq = (struct clib_deque*)malloc(sizeof(struct clib_deque));
    if (pDeq == (struct clib_deque*)0) {
        return (struct clib_deque*)0;
    }
    pDeq->no_max_elements = deq_size < 8 ? 8 : deq_size;
    pDeq->pElements = (struct clib_object**) malloc(pDeq->no_max_elements * sizeof(struct clib_object*));

    if (pDeq == (struct clib_deque*)0) {
        return (struct clib_deque*)0;
    }
    pDeq->compare_fn = fn_c;
    pDeq->destruct_fn = fn_d;
    pDeq->head = (int)pDeq->no_max_elements / 2;
    pDeq->tail = pDeq->head + 1;
    pDeq->no_of_elements = 0;

    return pDeq;
}

clib_error push_back_c_deque(struct clib_deque* pDeq, void* elem, size_t elem_size) {
    if (pDeq == (struct clib_deque*)0) {
        return CLIB_DEQUE_NOT_INITIALIZED;
    }
    if (pDeq->tail == pDeq->no_max_elements) {
        pDeq = grow_deque(pDeq);
    }
    insert_c_deque(pDeq, pDeq->tail, elem, elem_size);
    pDeq->tail++;

    return CLIB_ERROR_SUCCESS;
}

clib_error push_front_c_deque(struct clib_deque* pDeq, void* elem, size_t elem_size) {
    clib_error rc = CLIB_ERROR_SUCCESS;
    int to = 0;
    int from = 0;
    int count = 0;

    if (pDeq->head == 0) {
        pDeq = grow_deque(pDeq);
        to = (pDeq->no_max_elements - pDeq->no_of_elements) / 2;
        from = pDeq->head + 1;
        count = pDeq->tail - from + 1;
        memmove(&(pDeq->pElements[to]), &(pDeq->pElements[from]), count * sizeof(struct clib_object*));
        pDeq->head = to - 1;
        pDeq->tail = pDeq->head + count;
    }
    insert_c_deque(pDeq, pDeq->head, elem, elem_size);
    pDeq->head--;
    return rc;
}

clib_error front_c_deque(struct clib_deque* pDeq, void* elem) {
    if (pDeq == (struct clib_deque*)0) {
        return CLIB_DEQUE_NOT_INITIALIZED;
    }
    element_at_c_deque(pDeq, pDeq->head + 1, elem);
    return CLIB_ERROR_SUCCESS;
}

clib_error back_c_deque(struct clib_deque* pDeq, void* elem) {
    if (pDeq == (struct clib_deque*)0) {
        return CLIB_DEQUE_NOT_INITIALIZED;
    }
    element_at_c_deque(pDeq, pDeq->tail - 1, elem);
    return CLIB_ERROR_SUCCESS;
}

clib_error pop_back_c_deque(struct clib_deque* pDeq) {
    if (pDeq == (struct clib_deque*)0) {
        return CLIB_DEQUE_NOT_INITIALIZED;
    }
    if (pDeq->destruct_fn) {
        void* elem;
        if (element_at_c_deque(pDeq, pDeq->tail - 1, &elem) == CLIB_ERROR_SUCCESS) {
            pDeq->destruct_fn(elem);
            free(elem);
        }
    }
    delete_clib_object(pDeq->pElements[pDeq->tail - 1]);
    pDeq->tail--;
    pDeq->no_of_elements--;

    return CLIB_ERROR_SUCCESS;
}

clib_error pop_front_c_deque(struct clib_deque* pDeq) {
    if (pDeq == (struct clib_deque*)0) {
        return CLIB_DEQUE_NOT_INITIALIZED;
    }
    if (pDeq->destruct_fn) {
        void* elem;
        if (element_at_c_deque(pDeq, pDeq->head + 1, &elem) == CLIB_ERROR_SUCCESS) {
            pDeq->destruct_fn(elem);
            free(elem);
        }
    }
    delete_clib_object(pDeq->pElements[pDeq->head + 1]);

    pDeq->head++;
    pDeq->no_of_elements--;

    return CLIB_ERROR_SUCCESS;
}

clib_bool empty_c_deque(struct clib_deque* pDeq) {
    if (pDeq == (struct clib_deque*)0) {
        return clib_true;
    }
    return pDeq->no_of_elements == 0 ? clib_true : clib_false;
}

int size_c_deque(struct clib_deque* pDeq) {
    if (pDeq == (struct clib_deque*)0) {
        return clib_true;
    }
    return pDeq->no_of_elements - 1;
}

clib_error element_at_c_deque(struct clib_deque* pDeq, int index, void**elem) {
    clib_error rc = CLIB_ERROR_SUCCESS;

    if (!pDeq) {
        return CLIB_DEQUE_NOT_INITIALIZED;
    }
    get_raw_clib_object(pDeq->pElements[index], elem);
    return rc;
}

clib_error delete_c_deque(struct clib_deque* pDeq) {
    int i = 0;

    if (pDeq == (struct clib_deque*)0) {
        return CLIB_ERROR_SUCCESS;
    }
    if (pDeq->destruct_fn) {
        for (i = pDeq->head + 1; i < pDeq->tail; i++) {
            void* elem;
            if (element_at_c_deque(pDeq, i, &elem) == CLIB_ERROR_SUCCESS) {
                pDeq->destruct_fn(elem);
                free(elem);
            }
        }
    }
    for (i = pDeq->head + 1; i < pDeq->tail; i++) {
        delete_clib_object(pDeq->pElements[i]);
    }
    free(pDeq->pElements);
    free(pDeq);

    return CLIB_ERROR_SUCCESS;
}

static struct clib_object * get_next_c_deque(struct clib_iterator* pIterator) {
    struct clib_deque *pDeq = (struct clib_deque*)pIterator->pContainer;
    int index = ((struct clib_iterator*)pIterator)->pCurrent;

    if (index < 0 || index >= pDeq->tail) {
        return (struct clib_object*)0;
    }
    pIterator->pCurrentElement = pDeq->pElements[pIterator->pCurrent++];
    return pIterator->pCurrentElement;
}

static void * get_value_c_deque(void* pObject) {
    void* elem;
    get_raw_clib_object(pObject, &elem);
    return elem;
}

static void replace_value_c_deque(struct clib_iterator *pIterator, void* elem, size_t elem_size) {
    struct clib_deque*  pDeq = (struct clib_deque*)pIterator->pContainer;
    if (pDeq->destruct_fn) {
        void* old_element;
        if (get_raw_clib_object(pIterator->pCurrentElement, &old_element) == CLIB_ERROR_SUCCESS) {
            pDeq->destruct_fn(old_element);
            free(old_element);
        }
    }
    replace_raw_clib_object(pIterator->pCurrentElement, elem, elem_size);
}

struct clib_iterator * new_iterator_c_deque(struct clib_deque* pDeq) {
    struct clib_iterator *itr = (struct clib_iterator*) calloc(1, sizeof(struct clib_iterator));
    itr->get_next = get_next_c_deque;
    itr->get_value = get_value_c_deque;
    itr->replace_value = replace_value_c_deque;
    itr->pCurrent = pDeq->head + 1;
    itr->pContainer = pDeq;
    return itr;
}

void delete_iterator_c_deque(struct clib_iterator* pItr) {
    free(pItr);
}


//==================== c_map.c =============================================
#include "c_lib.h"
#include <stdio.h>

struct clib_map * new_c_map(clib_compare fn_c_k, clib_destroy fn_k_d, clib_destroy fn_v_d) {
    struct clib_map* pMap = (struct clib_map*)malloc(sizeof(struct clib_map));
    if (pMap == (struct clib_map*)0) {
        return (struct clib_map*)0;
    }
    pMap->root = new_c_rb(fn_c_k, fn_k_d, fn_v_d);
    if (pMap->root == (struct clib_rb*)0) {
        return (struct clib_map*)0;
    }
    return pMap;
}

clib_error insert_c_map(struct clib_map* pMap, void* key, size_t key_size, void* value, size_t value_size) {
    if (pMap == (struct clib_map*)0) {
        return CLIB_MAP_NOT_INITIALIZED;
    }
    return insert_c_rb(pMap->root, key, key_size, value, value_size);
}

clib_bool exists_c_map(struct clib_map* pMap, void* key) {
    clib_bool found = clib_false;
    struct clib_rb_node* node;

    if (pMap == (struct clib_map*)0) {
        return clib_false;
    }
    node = find_c_rb(pMap->root, key);
    if (node != (struct clib_rb_node*)0) {
        return clib_true;
    }
    return found;
}

clib_error remove_c_map(struct clib_map* pMap, void* key) {
    clib_error rc = CLIB_ERROR_SUCCESS;
    struct clib_rb_node* node;
    if (pMap == (struct clib_map*)0) {
        return CLIB_MAP_NOT_INITIALIZED;
    }
    node = remove_c_rb(pMap->root, key);
    if (node != (struct clib_rb_node*)0) {
        void* removed_node;
        if (pMap->root->destruct_k_fn) {
            if (get_raw_clib_object(node->key, &removed_node) == CLIB_ERROR_SUCCESS) {
                pMap->root->destruct_k_fn(removed_node);
                free(removed_node);
            }
        }
        delete_clib_object(node->key);

        if (pMap->root->destruct_v_fn) {
            if (get_raw_clib_object(node->value, &removed_node) == CLIB_ERROR_SUCCESS) {
                pMap->root->destruct_v_fn(removed_node);
                free(removed_node);
            }
        }
        delete_clib_object(node->value);

        free(node);
    }
    return rc;
}

clib_bool find_c_map(struct clib_map* pMap, void* key, void**value) {
    struct clib_rb_node* node;

    if (pMap == (struct clib_map*)0) {
        return clib_false;
    }
    node = find_c_rb(pMap->root, key);
    if (node == (struct clib_rb_node*)0) {
        return clib_false;
    }
    if (value) {
        get_raw_clib_object(node->value, value);
    }

    return clib_true;
}

clib_error delete_c_map(struct clib_map* x) {
    clib_error rc = CLIB_ERROR_SUCCESS;
    if (x != (struct clib_map*)0) {
        rc = delete_c_rb(x->root);
        free(x);
    }
    return rc;
}

static struct clib_rb_node * minimum_c_map(struct clib_map *x) {
    return minimum_c_rb(x->root, x->root->root);
}

static struct clib_object * get_next_c_map(struct clib_iterator* pIterator) {
    if (!pIterator->pCurrentElement) {
        pIterator->pCurrentElement = minimum_c_map(pIterator->pContainer);
    } else {
        struct clib_map *x = (struct clib_map*)pIterator->pContainer;
        pIterator->pCurrentElement = tree_successor(x->root, pIterator->pCurrentElement);
    }
    if (!pIterator->pCurrentElement)
        return (struct clib_object*)0;

    return ((struct clib_rb_node*)pIterator->pCurrentElement)->value;
}

static void * get_value_c_map(void* pObject) {
    void* elem;
    get_raw_clib_object(pObject, &elem);
    return elem;
}

static void replace_value_c_map(struct clib_iterator *pIterator, void* elem, size_t elem_size) {
    struct clib_map*  pMap = (struct clib_map*)pIterator->pContainer;

    if (pMap->root->destruct_v_fn) {
        void* old_element;
        if (get_raw_clib_object(pIterator->pCurrentElement, &old_element) == CLIB_ERROR_SUCCESS) {
            pMap->root->destruct_v_fn(old_element);
            free(old_element);
        }
    }
    replace_raw_clib_object(((struct clib_rb_node*)pIterator->pCurrentElement)->value, elem, elem_size);
}

struct clib_iterator * new_iterator_c_map(struct clib_map *pMap) {
    struct clib_iterator *itr = (struct clib_iterator*) malloc(sizeof(struct clib_iterator));
    itr->get_next = get_next_c_map;
    itr->get_value = get_value_c_map;
    itr->replace_value = replace_value_c_map;
    itr->pContainer = pMap;
    itr->pCurrent = 0;
    itr->pCurrentElement = (void*)0;
    return itr;
}

void delete_iterator_c_map(struct clib_iterator *pItr) {
    free(pItr);
}


//==================== c_rb.c =============================================
#include "c_lib.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>

#define rb_sentinel &pTree->sentinel

static void debug_verify_properties(struct clib_rb*);
static void debug_verify_property_1(struct clib_rb*, struct clib_rb_node*);
static void debug_verify_property_2(struct clib_rb*, struct clib_rb_node*);
static int debug_node_color(struct clib_rb*, struct clib_rb_node* n);
static void debug_verify_property_4(struct clib_rb*, struct clib_rb_node*);
static void debug_verify_property_5(struct clib_rb*, struct clib_rb_node*);
static void debug_verify_property_5_helper(struct clib_rb*, struct clib_rb_node*, int, int*);


static void __left_rotate(struct clib_rb* pTree, struct clib_rb_node* x) {
    struct clib_rb_node* y;
    y = x->right;
    x->right = y->left;
    if (y->left != rb_sentinel) {
        y->left->parent = x;
    }
    if (y != rb_sentinel) {
        y->parent = x->parent;
    }
    if (x->parent) {
        if (x == x->parent->left) {
            x->parent->left = y;
        } else {
            x->parent->right = y;
        }
    } else {
        pTree->root = y;
    }
    y->left = x;
    if (x != rb_sentinel) {
        x->parent = y;
    }
}

static void __right_rotate(struct clib_rb* pTree, struct clib_rb_node* x) {
    struct clib_rb_node* y = x->left;
    x->left = y->right;
    if (y->right != rb_sentinel) {
        y->right->parent = x;
    }
    if (y != rb_sentinel) {
        y->parent = x->parent;
    }
    if (x->parent) {
        if (x == x->parent->right) {
            x->parent->right = y;
        } else {
            x->parent->left = y;
        }
    } else {
        pTree->root = y;
    }
    y->right = x;
    if (x != rb_sentinel) {
        x->parent = y;
    }
}

struct clib_rb * new_c_rb(clib_compare fn_c, clib_destroy fn_ed, clib_destroy fn_vd) {
    struct clib_rb* pTree = (struct clib_rb*)calloc(1, sizeof(struct clib_rb));
    if (pTree == (struct clib_rb*)0) {
        return (struct clib_rb*)0;
    }
    pTree->compare_fn = fn_c;
    pTree->destruct_k_fn = fn_ed;
    pTree->destruct_v_fn = fn_vd;
    pTree->root = rb_sentinel;
    pTree->sentinel.left = rb_sentinel;
    pTree->sentinel.right = rb_sentinel;
    pTree->sentinel.parent = (struct clib_rb_node*)0;
    pTree->sentinel.color = clib_black;

    return pTree;
}

static void __rb_insert_fixup(struct clib_rb* pTree, struct clib_rb_node* x) {
    while (x != pTree->root && x->parent->color == clib_red) {
        if (x->parent == x->parent->parent->left) {
            struct clib_rb_node* y = x->parent->parent->right;
            if (y->color == clib_red) {
                x->parent->color = clib_black;
                y->color = clib_black;
                x->parent->parent->color = clib_red;
                x = x->parent->parent;
            } else {
                if (x == x->parent->right) {
                    x = x->parent;
                    __left_rotate(pTree, x);
                }
                x->parent->color = clib_black;
                x->parent->parent->color = clib_red;
                __right_rotate(pTree, x->parent->parent);
            }
        } else {
            struct clib_rb_node* y = x->parent->parent->left;
            if (y->color == clib_red) {
                x->parent->color = clib_black;
                y->color = clib_black;
                x->parent->parent->color = clib_red;
                x = x->parent->parent;
            } else {
                if (x == x->parent->left) {
                    x = x->parent;
                    __right_rotate(pTree, x);
                }
                x->parent->color = clib_black;
                x->parent->parent->color = clib_red;
                __left_rotate(pTree, x->parent->parent);
            }
        }
    }
    pTree->root->color = clib_black;
}

struct clib_rb_node * find_c_rb(struct clib_rb* pTree, void* key) {
    struct clib_rb_node* x = pTree->root;

    while (x != rb_sentinel) {
        int c = 0;
        void* cur_key;
        get_raw_clib_object(x->key, &cur_key);
        c = pTree->compare_fn(key, cur_key);
        free(cur_key);
        if (c == 0) {
            break;
        } else {
            x = c < 0 ? x->left : x->right;
        }
    }
    if (x == rb_sentinel) {
        return (struct clib_rb_node*)0;
    }
    return x;
}

clib_error insert_c_rb(struct clib_rb* pTree, void* k, size_t key_size, void* v, size_t value_size) {
    clib_error rc = CLIB_ERROR_SUCCESS;
    struct clib_rb_node* x;
    struct clib_rb_node* y;
    struct clib_rb_node* z;

    x = (struct clib_rb_node*)calloc(1, sizeof(struct clib_rb_node));
    if (x == (struct clib_rb_node*)0) {
        return CLIB_ERROR_MEMORY;
    }
    x->left = rb_sentinel;
    x->right = rb_sentinel;
    x->color = clib_red;

    x->key = new_clib_object(k, key_size);
    if (v) {
        x->value = new_clib_object(v, value_size);
    } else {
        x->value = (struct clib_object*)0;
    }

    y = pTree->root;
    z = (struct clib_rb_node*)0;

    while (y != rb_sentinel) {
        int c = 0;
        void* cur_key;
        void* new_key;

        get_raw_clib_object(y->key, &cur_key);
        get_raw_clib_object(x->key, &new_key);

        c = (pTree->compare_fn) (new_key, cur_key);
        free(cur_key);
        free(new_key);
        if (c == 0) {
            /* TODO : Delete node here */
            return CLIB_RBTREE_KEY_DUPLICATE;
        }
        z = y;
        if (c < 0) {
            y = y->left;
        } else {
            y = y->right;
        }
    }
    x->parent = z;
    if (z) {
        int c = 0;
        void* cur_key;
        void* new_key;
        get_raw_clib_object(z->key, &cur_key);
        get_raw_clib_object(x->key, &new_key);

        c = pTree->compare_fn(new_key, cur_key);
        free(cur_key);
        free(new_key);
        if (c < 0) {
            z->left = x;
        } else {
            z->right = x;
        }
    } else {
        pTree->root = x;
    }
    __rb_insert_fixup(pTree, x);

    debug_verify_properties(pTree);
    return rc;
}

static void __rb_remove_fixup(struct clib_rb* pTree, struct clib_rb_node* x) {
    while (x != pTree->root && x->color == clib_black) {
        if (x == x->parent->left) {
            struct clib_rb_node* w = x->parent->right;
            if (w->color == clib_red) {
                w->color = clib_black;
                x->parent->color = clib_red;
                __left_rotate(pTree, x->parent);
                w = x->parent->right;
            }
            if (w->left->color == clib_black && w->right->color == clib_black) {
                w->color = clib_red;
                x = x->parent;
            } else {
                if (w->right->color == clib_black) {
                    w->left->color = clib_black;
                    w->color = clib_red;
                    __right_rotate(pTree, w);
                    w = x->parent->right;
                }
                w->color = x->parent->color;
                x->parent->color = clib_black;
                w->right->color = clib_black;
                __left_rotate(pTree, x->parent);
                x = pTree->root;
            }
        } else {
            struct clib_rb_node* w = x->parent->left;
            if (w->color == clib_red) {
                w->color = clib_black;
                x->parent->color = clib_red;
                __right_rotate(pTree, x->parent);
                w = x->parent->left;
            }
            if (w->right->color == clib_black && w->left->color == clib_black) {
                w->color = clib_red;
                x = x->parent;
            } else {
                if (w->left->color == clib_black) {
                    w->right->color = clib_black;
                    w->color = clib_red;
                    __left_rotate(pTree, w);
                    w = x->parent->left;
                }
                w->color = x->parent->color;
                x->parent->color = clib_black;
                w->left->color = clib_black;
                __right_rotate(pTree, x->parent);
                x = pTree->root;
            }
        }
    }
    x->color = clib_black;
}

static struct clib_rb_node * __remove_c_rb(struct clib_rb* pTree, struct clib_rb_node* z) {
    struct clib_rb_node* x = (struct clib_rb_node*)0;
    struct clib_rb_node* y = (struct clib_rb_node*)0;

    if (z->left == rb_sentinel || z->right == rb_sentinel) {
        y = z;
    } else {
        y = z->right;
        while (y->left != rb_sentinel) {
            y = y->left;
        }
    }
    if (y->left != rb_sentinel) {
        x = y->left;
    } else {
        x = y->right;
    }
    x->parent = y->parent;
    if (y->parent) {
        if (y == y->parent->left) {
            y->parent->left = x;
        } else {
            y->parent->right = x;
        }
    } else {
        pTree->root = x;
    }
    if (y != z) {
        struct clib_object* tmp;
        tmp = z->key;
        z->key = y->key;
        y->key = tmp;

        tmp = z->value;
        z->value = y->value;
        y->value = tmp;
    }
    if (y->color == clib_black) {
        __rb_remove_fixup(pTree, x);
    }
    debug_verify_properties(pTree);
    return y;
}

struct clib_rb_node * remove_c_rb(struct clib_rb* pTree, void* key) {
    struct clib_rb_node* z = (struct clib_rb_node*)0;

    z = pTree->root;
    while (z != rb_sentinel) {
        int c = 0;
        void* cur_key;
        get_raw_clib_object(z->key, &cur_key);
        c = pTree->compare_fn(key, cur_key);
        free(cur_key);
        if (c == 0) {
            break;
        } else {
            z = (c < 0) ? z->left : z->right;
        }
    }
    if (z == rb_sentinel) {
        return (struct clib_rb_node*)0;
    }
    return __remove_c_rb(pTree, z);
}

static void __delete_c_rb_node(struct clib_rb* pTree, struct clib_rb_node* x) {
    void* key;
    void* value;

    if (pTree->destruct_k_fn) {
        get_raw_clib_object(x->key, &key);
        pTree->destruct_k_fn(key);
        free(key);
    }
    delete_clib_object(x->key);

    if (x->value) {
        if (pTree->destruct_v_fn) {
            get_raw_clib_object(x->value, &value);
            pTree->destruct_v_fn(value);
            free(value);
        }
        delete_clib_object(x->value);
    }
}

clib_error delete_c_rb(struct clib_rb* pTree) {
    clib_error rc = CLIB_ERROR_SUCCESS;
    struct clib_rb_node* z = pTree->root;

    while (z != rb_sentinel) {
        if (z->left != rb_sentinel) {
            z = z->left;
        } else if (z->right != rb_sentinel) {
            z = z->right;
        } else {
            __delete_c_rb_node(pTree, z);
            if (z->parent) {
                z = z->parent;
                if (z->left != rb_sentinel) {
                    free(z->left);
                    z->left = rb_sentinel;
                } else if (z->right != rb_sentinel) {
                    free(z->right);
                    z->right = rb_sentinel;
                }
            } else {
                free(z);
                z = rb_sentinel;
            }
        }
    }
    free(pTree);
    return rc;
}

struct clib_rb_node * minimum_c_rb(struct clib_rb* pTree, struct clib_rb_node* x) {
    while (x->left != rb_sentinel) {
        x = x->left;
    }
    return x;
}

struct clib_rb_node * maximum_c_rb(struct clib_rb* pTree, struct clib_rb_node* x) {
    while (x->right != rb_sentinel) {
        x = x->right;
    }
    return x;
}

clib_bool empty_c_rb(struct clib_rb* pTree) {
    if (pTree->root != rb_sentinel) {
        return clib_true;
    }
    return clib_false;
}

struct clib_rb_node * tree_successor(struct clib_rb* pTree, struct clib_rb_node* x) {
    struct clib_rb_node *y = (struct clib_rb_node*)0;
    if (x->right != rb_sentinel) {
        return minimum_c_rb(pTree, x->right);
    }
    if (x == maximum_c_rb(pTree, pTree->root)) {
        return (struct clib_rb_node*)0;
    }
    y = x->parent;
    while (y != rb_sentinel && x == y->right) {
        x = y;
        y = y->parent;
    }
    return y;
}

/*
struct clib_rb_node * get_next_c_rb(struct clib_rb* pTree, struct clib_rb_node**current, struct clib_rb_node**pre) {
    struct clib_rb_node* prev_current;
    while ((*current) != rb_sentinel) {
        if ((*current)->left == rb_sentinel) {
            prev_current = (*current);
            (*current) = (*current)->right;
            return prev_current->raw_data.key;
        } else {
            (*pre) = (*current)->left;
            while ((*pre)->right != rb_sentinel && (*pre)->right != (*current)) {
                (*pre) = (*pre)->right;
            }
            if ((*pre)->right == rb_sentinel) {
                (*pre)->right = (*current);
                (*current) = (*current)->left;
            } else {
                (*pre)->right = rb_sentinel;
                prev_current = (*current);
                (*current) = (*current)->right;
                return prev_current->raw_data.key;
            }
        }
    }
    return (struct clib_rb_node*)0;
}
// */

void debug_verify_properties(struct clib_rb* t) {
    debug_verify_property_1(t, t->root);
    debug_verify_property_2(t, t->root);
    debug_verify_property_4(t, t->root);
    debug_verify_property_5(t, t->root);
}

void debug_verify_property_1(struct clib_rb* pTree, struct clib_rb_node* n) {
    assert(debug_node_color(pTree, n) == clib_red || debug_node_color(pTree, n) == clib_black);
    if (n == rb_sentinel) { return; }
    debug_verify_property_1(pTree, n->left);
    debug_verify_property_1(pTree, n->right);
}

void debug_verify_property_2(struct clib_rb* pTree, struct clib_rb_node* root) {
    assert(debug_node_color(pTree, root) == clib_black);
}

int debug_node_color(struct clib_rb* pTree, struct clib_rb_node* n) {
    return n == rb_sentinel ? clib_black : n->color;
}

void debug_verify_property_4(struct clib_rb* pTree, struct clib_rb_node* n) {
    if (debug_node_color(pTree, n) == clib_red) {
        assert(debug_node_color(pTree, n->left) == clib_black);
        assert(debug_node_color(pTree, n->right) == clib_black);
        assert(debug_node_color(pTree, n->parent) == clib_black);
    }
    if (n == rb_sentinel) { return; }
    debug_verify_property_4(pTree, n->left);
    debug_verify_property_4(pTree, n->right);
}

void debug_verify_property_5(struct clib_rb* pTree, struct clib_rb_node* root) {
    int black_count_path = -1;
    debug_verify_property_5_helper(pTree, root, 0, &black_count_path);
}

void debug_verify_property_5_helper(struct clib_rb* pTree, struct clib_rb_node* n, int black_count, int* path_black_count) {
    if (debug_node_color(pTree, n) == clib_black) {
        black_count++;
    }
    if (n == rb_sentinel) {
        if (*path_black_count == -1) {
            *path_black_count = black_count;
        } else {
            assert(black_count == *path_black_count);
        }
        return;
    }
    debug_verify_property_5_helper(pTree, n->left, black_count, path_black_count);
    debug_verify_property_5_helper(pTree, n->right, black_count, path_black_count);
}


//==================== c_set.c =============================================
#include "c_lib.h"

#include <stdio.h>

struct clib_set * new_c_set(clib_compare fn_c, clib_destroy fn_d) {
    struct clib_set* pSet = (struct clib_set*)malloc(sizeof(struct clib_set));
    if (pSet == (struct clib_set*)0) {
        return (struct clib_set*)0;
    }
    pSet->root = new_c_rb(fn_c, fn_d, (void*)0);
    if (pSet->root == (struct clib_rb*)0) {
        return (struct clib_set*)0;
    }
    return pSet;
}

clib_error insert_c_set(struct clib_set* pSet, void* key, size_t key_size) {
    if (pSet == (struct clib_set*)0) {
        return CLIB_SET_NOT_INITIALIZED;
    }
    return insert_c_rb(pSet->root, key, key_size, (void*)0, 0);
}

clib_bool exists_c_set(struct clib_set* pSet, void* key) {
    clib_bool found = clib_false;
    struct clib_rb_node* node;

    if (pSet == (struct clib_set*)0) {
        return clib_false;
    }
    node = find_c_rb(pSet->root, key);
    if (node != (struct clib_rb_node*)0) {
        return clib_true;
    }
    return found;
}

clib_error remove_c_set(struct clib_set* pSet, void* key) {
    clib_error rc = CLIB_ERROR_SUCCESS;
    struct clib_rb_node* node;
    if (pSet == (struct clib_set*)0) {
        return CLIB_SET_NOT_INITIALIZED;
    }
    node = remove_c_rb(pSet->root, key);
    if (node != (struct clib_rb_node*)0) {
        if (pSet->root->destruct_k_fn) {
            void* key = (void*)0;
            if (CLIB_ERROR_SUCCESS == get_raw_clib_object(node->key, &key)) {
                pSet->root->destruct_k_fn(key);
                free(key);
            }
        }
        delete_clib_object(node->key);

        free(node);
    }
    return rc;
}

clib_bool find_c_set(struct clib_set* pSet, void* key, void* outKey) {
    struct clib_rb_node* node;

    if (pSet == (struct clib_set*)0) {
        return clib_false;
    }
    node = find_c_rb(pSet->root, key);
    if (node == (struct clib_rb_node*)0) {
        return clib_false;
    }
    get_raw_clib_object(node->key, outKey);

    return clib_true;
}

clib_error delete_c_set(struct clib_set* x) {
    clib_error rc = CLIB_ERROR_SUCCESS;
    if (x != (struct clib_set*)0) {
        rc = delete_c_rb(x->root);
        free(x);
    }
    return rc;
}

static struct clib_rb_node * minimum_c_set(struct clib_set *x) {
    return minimum_c_rb(x->root, x->root->root);
}

static struct clib_object * get_next_c_set(struct clib_iterator* pIterator) {
    if (!pIterator->pCurrentElement) {
        pIterator->pCurrentElement = minimum_c_set(pIterator->pContainer);
    } else {
        struct clib_set *x = (struct clib_set*)pIterator->pContainer;
        pIterator->pCurrentElement = tree_successor(x->root, pIterator->pCurrentElement);
    }
    if (!pIterator->pCurrentElement) {
        return (struct clib_object*)0;
    }
    return ((struct clib_rb_node*)pIterator->pCurrentElement)->key;
}

static void * get_value_c_set(void* pObject) {
    void* elem;
    get_raw_clib_object(pObject, &elem);
    return elem;
}

struct clib_iterator * new_iterator_c_set(struct clib_set* pSet) {
    struct clib_iterator *itr = (struct clib_iterator*) calloc(1, sizeof(struct clib_iterator));
    itr->get_next = get_next_c_set;
    itr->get_value = get_value_c_set;
    itr->pContainer = pSet;
    itr->pCurrent = 0;
    itr->pCurrentElement = (void*)0;
    return itr;
}

void delete_iterator_c_set(struct clib_iterator* pItr) {
    free(pItr);
}


//==================== c_slist.c =============================================
#include "c_lib.h"

struct clib_slist * new_c_slist(clib_destroy fn_d, clib_compare fn_c) {
    struct clib_slist* pSlist = (struct clib_slist*)malloc(sizeof(struct clib_slist));
    pSlist->head = (struct clib_slist_node*)0;
    pSlist->destruct_fn = fn_d;
    pSlist->compare_key_fn = fn_c;
    pSlist->size = 0;
    return pSlist;
}

void delete_c_slist(struct clib_slist* pSlist) {
    while (pSlist->size != 0) {
        remove_c_slist(pSlist, 0);
    }
    free(pSlist);
}

clib_error push_back_c_slist(struct clib_slist* pSlist, void* elem, size_t elem_size) {
    struct clib_slist_node* current = (struct clib_slist_node*)0;
    struct clib_slist_node* new_node = (struct clib_slist_node*)0;

    new_node = (struct clib_slist_node*)malloc(sizeof(struct clib_slist_node));

    new_node->elem = new_clib_object(elem, elem_size);
    if (!new_node->elem) {
        return CLIB_SLIST_INSERT_FAILED;
    }
    new_node->next = (struct clib_slist_node*)0;

    if (pSlist->head == (struct clib_slist_node*)0) {
        pSlist->head = new_node;
        pSlist->size++;
        return CLIB_ERROR_SUCCESS;
    }
    current = pSlist->head;
    while (current->next != (struct clib_slist_node*)0) {
        current = current->next;
    }
    current->next = new_node;
    pSlist->size++;

    return CLIB_ERROR_SUCCESS;
}

static void __remove_c_list(struct clib_slist* pSlist, struct clib_slist_node* pSlistNode) {
    if (pSlist->destruct_fn) {
        void* elem;
        if (get_raw_clib_object(pSlistNode->elem, &elem) == CLIB_ERROR_SUCCESS) {
            pSlist->destruct_fn(elem);
            free(elem);
        }
    }
    delete_clib_object(pSlistNode->elem);

    free(pSlistNode);
}

void remove_c_slist(struct clib_slist* pSlist, int pos) {
    int i = 0;

    struct clib_slist_node* current = pSlist->head;
    struct clib_slist_node* temp = (struct clib_slist_node*)0;

    if (pos > pSlist->size) return;

    if (pos == 0) {
        pSlist->head = current->next;
        __remove_c_list(pSlist, current);
        pSlist->size--;
        return;
    }
    for (i = 1; i < pos - 1; i++) {
        current = current->next;
    }

    temp = current->next;
    current->next = current->next->next;
    __remove_c_list(pSlist, temp);

    pSlist->size--;
}

clib_error insert_c_slist(struct clib_slist* pSlist, int pos, void* elem, size_t elem_size) {
    int i = 0;
    struct clib_slist_node* current = pSlist->head;
    struct clib_slist_node* new_node = (struct clib_slist_node*)0;

    if (pos == 1) {
        new_node = (struct clib_slist_node*)malloc(sizeof(struct clib_slist_node));
        new_node->elem = new_clib_object(elem, elem_size);
        if (!new_node->elem) {
            free(new_node);
            return CLIB_SLIST_INSERT_FAILED;
        }
        new_node->next = pSlist->head;
        pSlist->head = new_node;
        pSlist->size++;
        return CLIB_ERROR_SUCCESS;
    }

    if (pos >= pSlist->size + 1) {
        return push_back_c_slist(pSlist, elem, elem_size);
    }

    for (i = 1; i < pos - 1; i++) {
        current = current->next;
    }
    new_node = (struct clib_slist_node*)malloc(sizeof(struct clib_slist_node));
    new_node->elem = new_clib_object(elem, elem_size);
    if (!new_node->elem) {
        free(new_node);
        return CLIB_SLIST_INSERT_FAILED;
    }

    new_node->next = current->next;
    current->next = new_node;
    pSlist->size++;

    return CLIB_ERROR_SUCCESS;
}

void for_each_c_slist(struct clib_slist* pSlist, void(*fn)(void*)) {
    void* elem;
    struct clib_slist_node* current = pSlist->head;
    while (current != (struct clib_slist_node*)0) {
        get_raw_clib_object(current->elem, &elem);
        (fn)(elem);
        free(elem);
        current = current->next;
    }
}

clib_bool find_c_slist(struct clib_slist* pSlist, void* find_value, void**out_value) {
    struct clib_slist_node* current = pSlist->head;
    while (current != (struct clib_slist_node*)0) {
        get_raw_clib_object(current->elem, out_value);
        if ((pSlist->compare_key_fn)(find_value, *out_value) != 0) {
            break;
        }
        free(*out_value);
        current = current->next;
    }
    if (current) {
        return clib_true;
    }
    return clib_false;
}

static struct clib_object * get_next_c_slist(struct clib_iterator* pIterator) {
    struct clib_slist *pSlist = (struct clib_slist*)pIterator->pContainer;
    if (!pIterator->pCurrentElement) {
        pIterator->pCurrentElement = (struct clib_slist_node*)pSlist->head;
    } else {
        pIterator->pCurrentElement = ((struct clib_slist_node*)pIterator->pCurrentElement)->next;
    }
    if (!pIterator->pCurrentElement) {
        return (struct clib_object*)0;
    }
    return ((struct clib_slist_node*)pIterator->pCurrentElement)->elem;
}

static void * get_value_c_slist(void* pObject) {
    void* elem;
    get_raw_clib_object(pObject, &elem);
    return elem;
}

static void replace_value_c_slist(struct clib_iterator *pIterator, void* elem, size_t elem_size) {
    struct clib_slist*  pSlist = (struct clib_slist*)pIterator->pContainer;
    struct clib_object *pObj = ((struct clib_slist_node*)pIterator->pCurrentElement)->elem;

    if (pSlist->destruct_fn) {
        void* old_element;
        if (get_raw_clib_object(pObj, &old_element) == CLIB_ERROR_SUCCESS) {
            pSlist->destruct_fn(old_element);
            free(old_element);
        }
    }
    replace_raw_clib_object(pObj, elem, elem_size);
}

struct clib_iterator * new_iterator_c_slist(struct clib_slist* pSlist) {
    struct clib_iterator *itr = (struct clib_iterator*) malloc(sizeof(struct clib_iterator));
    itr->get_next = get_next_c_slist;
    itr->get_value = get_value_c_slist;
    itr->replace_value = replace_value_c_slist;
    itr->pContainer = pSlist;
    itr->pCurrentElement = (void*)0;
    itr->pCurrent = 0;
    return itr;
}

void delete_iterator_c_slist(struct clib_iterator* pItr) {
    free(pItr);
}

//==================== c_util.c =============================================
#include "c_lib.h"
#include <string.h>
#include <stdlib.h>

void clib_copy(void* destination, void* source, size_t size) {
    memcpy((char*)destination, source, size);
}

void clib_get(void* destination, void* source, size_t size) {
    memcpy(destination, (char*)source, size);
}

struct clib_object * new_clib_object(void* inObject, size_t obj_size) {
    struct clib_object* tmp = (struct clib_object*)malloc(sizeof(struct clib_object));
    if (!tmp) {
        return (struct clib_object*)0;
    }
    tmp->size = obj_size;
    tmp->raw_data = (void*)malloc(obj_size);
    if (!tmp->raw_data) {
        free(tmp);
        return (struct clib_object*)0;
    }
    memcpy(tmp->raw_data, inObject, obj_size);
    return tmp;
}

clib_error get_raw_clib_object(struct clib_object *inObject, void**elem) {
    *elem = (void*)malloc(inObject->size);
    if (!*elem) {
        return CLIB_ELEMENT_RETURN_ERROR;
    }
    memcpy(*elem, inObject->raw_data, inObject->size);

    return CLIB_ERROR_SUCCESS;
}

void replace_raw_clib_object(struct clib_object* current_object, void* elem, size_t elem_size) {
    free(current_object->raw_data);
    current_object->raw_data = (void*)malloc(elem_size);
    memcpy(current_object->raw_data, elem, elem_size);
}

void delete_clib_object(struct clib_object* inObject) {
    if (inObject) {
        free(inObject->raw_data);
        free(inObject);
    }
}

char * clib_strdup(char *ptr) {
#ifdef WIN32
    return _strdup(ptr);
#else
    return strdup(ptr);
#endif
}
