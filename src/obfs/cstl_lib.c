/** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** **
 *  This file is part of cstl library
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

#include "cstl_lib.h"
#include <string.h>
#include <stdio.h>

// c_algorithms.c
#include <stdlib.h>

void
cstl_for_each(struct cstl_iterator *pIterator, void(*fn)(void*)) {
    struct cstl_object *pElement;

    pElement = pIterator->get_next(pIterator);
    while (pElement) {
        void *value = pIterator->get_value(pElement);
        (fn)(value);
        free(value);
        pElement = pIterator->get_next(pIterator);
    }
}


// c_array.c
#include <string.h>
#include <stdio.h>

static struct cstl_array*
array_check_and_grow(struct cstl_array* pArray) {
    if (pArray->no_of_elements >= pArray->no_max_elements) {
        pArray->no_max_elements = 2 * pArray->no_max_elements;
        pArray->pElements = (struct cstl_object**) realloc(pArray->pElements,
            pArray->no_max_elements * sizeof(struct cstl_object*));
    }
    return pArray;
}

struct cstl_array*
cstl_array_new(int array_size, cstl_compare fn_c, cstl_destroy fn_d) {
    struct cstl_array* pArray = (struct cstl_array*)calloc(1, sizeof(struct cstl_array));
    if (!pArray) {
        return (struct cstl_array*)0;
    }
    pArray->no_max_elements = array_size < 8 ? 8 : array_size;
    pArray->pElements = (struct cstl_object**) calloc(pArray->no_max_elements, sizeof(struct cstl_object*));
    if (!pArray->pElements) {
        free(pArray);
        return (struct cstl_array*)0;
    }
    pArray->compare_fn = fn_c;
    pArray->destruct_fn = fn_d;
    pArray->no_of_elements = 0;

    return pArray;
}

static cstl_error
insert_c_array(struct cstl_array* pArray, int index, void* elem, size_t elem_size) {
    cstl_error rc = CSTL_ERROR_SUCCESS;
    struct cstl_object* pObject = cstl_object_new(elem, elem_size);
    if (!pObject) {
        return CSTL_ARRAY_INSERT_FAILED;
    }
    pArray->pElements[index] = pObject;
    pArray->no_of_elements++;
    return rc;
}

cstl_error
cstl_array_push_back(struct cstl_array* pArray, void* elem, size_t elem_size) {
    cstl_error rc = CSTL_ERROR_SUCCESS;

    if (!pArray) {
        return CSTL_ARRAY_NOT_INITIALIZED;
    }
    array_check_and_grow(pArray);

    rc = insert_c_array(pArray, pArray->no_of_elements, elem, elem_size);

    return rc;
}

cstl_error
cstl_array_element_at(struct cstl_array* pArray, int index, void** elem) {
    cstl_error rc = CSTL_ERROR_SUCCESS;

    if (!pArray) {
        return CSTL_ARRAY_NOT_INITIALIZED;
    }
    if (index < 0 || index > pArray->no_max_elements) {
        return CSTL_ARRAY_INDEX_OUT_OF_BOUND;
    }
    cstl_object_get_raw(pArray->pElements[index], elem);
    return rc;
}

int
cstl_array_size(struct cstl_array* pArray) {
    if (pArray == (struct cstl_array*)0) {
        return 0;
    }
    return pArray->no_of_elements - 1;
}

int
cstl_array_capacity(struct cstl_array* pArray) {
    if (pArray == (struct cstl_array*)0) {
        return 0;
    }
    return pArray->no_max_elements;
}

cstl_bool
cstl_array_empty(struct cstl_array* pArray) {
    if (pArray == (struct cstl_array*)0) {
        return 0;
    }
    return pArray->no_of_elements == 0 ? cstl_true : cstl_false;
}

cstl_error
cstl_array_reserve(struct cstl_array* pArray, int new_size) {
    if (pArray == (struct cstl_array*)0) {
        return CSTL_ARRAY_NOT_INITIALIZED;
    }
    if (new_size <= pArray->no_max_elements) {
        return CSTL_ERROR_SUCCESS;
    }
    array_check_and_grow(pArray);
    return CSTL_ERROR_SUCCESS;
}

cstl_error
cstl_array_front(struct cstl_array* pArray, void* elem) {
    return cstl_array_element_at(pArray, 0, elem);
}

cstl_error
cstl_array_back(struct cstl_array* pArray, void* elem) {
    return cstl_array_element_at(pArray, pArray->no_of_elements - 1, elem);
}

cstl_error
cstl_array_insert_at(struct cstl_array* pArray, int index, void* elem, size_t elem_size) {
    cstl_error rc = CSTL_ERROR_SUCCESS;
    if (!pArray) {
        return CSTL_ARRAY_NOT_INITIALIZED;
    }
    if (index < 0 || index > pArray->no_max_elements) {
        return CSTL_ARRAY_INDEX_OUT_OF_BOUND;
    }
    array_check_and_grow(pArray);

    memmove(&(pArray->pElements[index + 1]),
        &pArray->pElements[index],
        (pArray->no_of_elements - index) * sizeof(struct cstl_object*));

    rc = insert_c_array(pArray, index, elem, elem_size);

    return rc;
}

cstl_error
cstl_array_remove_from(struct cstl_array* pArray, int index) {
    cstl_error   rc = CSTL_ERROR_SUCCESS;

    if (!pArray) {
        return rc;
    }
    if (index < 0 || index > pArray->no_max_elements) {
        return CSTL_ARRAY_INDEX_OUT_OF_BOUND;
    }
    if (pArray->destruct_fn) {
        void* elem;
        if (CSTL_ERROR_SUCCESS == cstl_array_element_at(pArray, index, &elem)) {
            pArray->destruct_fn(elem);
            free(elem);
        }
    }
    cstl_object_delete(pArray->pElements[index]);

    memmove(&(pArray->pElements[index]),
        &pArray->pElements[index + 1],
        (pArray->no_of_elements - index) * sizeof(struct cstl_object*));
    pArray->no_of_elements--;

    return rc;
}

cstl_error
cstl_array_delete(struct cstl_array* pArray) {
    cstl_error rc = CSTL_ERROR_SUCCESS;
    int i = 0;

    if (pArray == (struct cstl_array*)0) {
        return rc;
    }
    if (pArray->destruct_fn) {
        for (i = 0; i < pArray->no_of_elements; i++) {
            void* elem;
            if (CSTL_ERROR_SUCCESS == cstl_array_element_at(pArray, i, &elem)) {
                pArray->destruct_fn(elem);
                free(elem);
            }
        }
    }

    for (i = 0; i < pArray->no_of_elements; i++) {
        cstl_object_delete(pArray->pElements[i]);
    }
    free(pArray->pElements);
    free(pArray);
    return rc;
}

static struct cstl_object*
get_next_c_array(struct cstl_iterator* pIterator) {
    struct cstl_array *pArray = (struct cstl_array*)pIterator->pContainer;
    if (pIterator->pCurrent > cstl_array_size(pArray)) {
        return (struct cstl_object*)0;
    }
    pIterator->pCurrentElement = pArray->pElements[pIterator->pCurrent++];
    return pIterator->pCurrentElement;
}

static void*
get_value_c_array(void* pObject) {
    void* elem;
    cstl_object_get_raw(pObject, &elem);
    return elem;
}

static void
replace_value_c_array(struct cstl_iterator *pIterator, void* elem, size_t elem_size) {
    struct cstl_array*  pArray = (struct cstl_array*)pIterator->pContainer;

    if (pArray->destruct_fn) {
        void* old_element;
        if (CSTL_ERROR_SUCCESS == cstl_object_get_raw(pIterator->pCurrentElement, &old_element)) {
            pArray->destruct_fn(old_element);
            free(old_element);
        }
    }
    cstl_object_replace_raw(pIterator->pCurrentElement, elem, elem_size);
}

struct cstl_iterator*
cstl_array_new_iterator(struct cstl_array* pArray) {
    struct cstl_iterator *itr = (struct cstl_iterator*) calloc(1, sizeof(struct cstl_iterator));
    itr->get_next = get_next_c_array;
    itr->get_value = get_value_c_array;
    itr->replace_value = replace_value_c_array;
    itr->pContainer = pArray;
    itr->pCurrent = 0;
    return itr;
}

void
cstl_array_delete_iterator(struct cstl_iterator* pItr) {
    free(pItr);
}


// c_deque.c
#include <string.h>

#define cstl_deque_INDEX(x)  ((char *)(pDeq)->pElements + (sizeof(struct cstl_object) * (x)))

static cstl_error
insert_c_deque(struct cstl_deque* pDeq, int index, void* elem, size_t elem_size) {
    cstl_error rc = CSTL_ERROR_SUCCESS;
    struct cstl_object* pObject = cstl_object_new(elem, elem_size);
    if (!pObject) {
        return CSTL_ARRAY_INSERT_FAILED;
    }
    pDeq->pElements[index] = pObject;
    pDeq->no_of_elements++;
    return rc;
}

static struct cstl_deque*
grow_deque(struct cstl_deque* pDeq) {
    pDeq->no_max_elements = pDeq->no_max_elements * 2;
    pDeq->pElements = (struct cstl_object**) realloc(pDeq->pElements,
        pDeq->no_max_elements * sizeof(struct cstl_object*));
    return pDeq;
}

struct cstl_deque*
cstl_deque_new(int deq_size, cstl_compare fn_c, cstl_destroy fn_d) {
    struct cstl_deque* pDeq = (struct cstl_deque*)calloc(1, sizeof(struct cstl_deque));
    if (pDeq == (struct cstl_deque*)0) {
        return (struct cstl_deque*)0;
    }
    pDeq->no_max_elements = deq_size < 8 ? 8 : deq_size;
    pDeq->pElements = (struct cstl_object**) calloc(pDeq->no_max_elements, sizeof(struct cstl_object*));

    if (pDeq == (struct cstl_deque*)0) {
        return (struct cstl_deque*)0;
    }
    pDeq->compare_fn = fn_c;
    pDeq->destruct_fn = fn_d;
    pDeq->head = (int)pDeq->no_max_elements / 2;
    pDeq->tail = pDeq->head + 1;
    pDeq->no_of_elements = 0;

    return pDeq;
}

cstl_error
cstl_deque_push_back(struct cstl_deque* pDeq, void* elem, size_t elem_size) {
    if (pDeq == (struct cstl_deque*)0) {
        return CSTL_DEQUE_NOT_INITIALIZED;
    }
    if (pDeq->tail == pDeq->no_max_elements) {
        pDeq = grow_deque(pDeq);
    }
    insert_c_deque(pDeq, pDeq->tail, elem, elem_size);
    pDeq->tail++;

    return CSTL_ERROR_SUCCESS;
}

cstl_error
cstl_deque_push_front(struct cstl_deque* pDeq, void* elem, size_t elem_size) {
    cstl_error rc = CSTL_ERROR_SUCCESS;
    int to = 0;
    int from = 0;
    int count = 0;

    if (pDeq->head == 0) {
        pDeq = grow_deque(pDeq);
        to = (pDeq->no_max_elements - pDeq->no_of_elements) / 2;
        from = pDeq->head + 1;
        count = pDeq->tail - from + 1;
        memmove(&(pDeq->pElements[to]), &(pDeq->pElements[from]), count * sizeof(struct cstl_object*));
        pDeq->head = to - 1;
        pDeq->tail = pDeq->head + count;
    }
    insert_c_deque(pDeq, pDeq->head, elem, elem_size);
    pDeq->head--;
    return rc;
}

cstl_error
cstl_deque_front(struct cstl_deque* pDeq, void* elem) {
    if (pDeq == (struct cstl_deque*)0) {
        return CSTL_DEQUE_NOT_INITIALIZED;
    }
    cstl_deque_element_at(pDeq, pDeq->head + 1, elem);
    return CSTL_ERROR_SUCCESS;
}

cstl_error
cstl_deque_back(struct cstl_deque* pDeq, void* elem) {
    if (pDeq == (struct cstl_deque*)0) {
        return CSTL_DEQUE_NOT_INITIALIZED;
    }
    cstl_deque_element_at(pDeq, pDeq->tail - 1, elem);
    return CSTL_ERROR_SUCCESS;
}

cstl_error
cstl_deque_pop_back(struct cstl_deque* pDeq) {
    if (pDeq == (struct cstl_deque*)0) {
        return CSTL_DEQUE_NOT_INITIALIZED;
    }
    if (pDeq->destruct_fn) {
        void* elem;
        if (cstl_deque_element_at(pDeq, pDeq->tail - 1, &elem) == CSTL_ERROR_SUCCESS) {
            pDeq->destruct_fn(elem);
            free(elem);
        }
    }
    cstl_object_delete(pDeq->pElements[pDeq->tail - 1]);
    pDeq->tail--;
    pDeq->no_of_elements--;

    return CSTL_ERROR_SUCCESS;
}

cstl_error
cstl_deque_pop_front(struct cstl_deque* pDeq) {
    if (pDeq == (struct cstl_deque*)0) {
        return CSTL_DEQUE_NOT_INITIALIZED;
    }
    if (pDeq->destruct_fn) {
        void* elem;
        if (cstl_deque_element_at(pDeq, pDeq->head + 1, &elem) == CSTL_ERROR_SUCCESS) {
            pDeq->destruct_fn(elem);
            free(elem);
        }
    }
    cstl_object_delete(pDeq->pElements[pDeq->head + 1]);

    pDeq->head++;
    pDeq->no_of_elements--;

    return CSTL_ERROR_SUCCESS;
}

cstl_bool
cstl_deque_empty(struct cstl_deque* pDeq) {
    if (pDeq == (struct cstl_deque*)0) {
        return cstl_true;
    }
    return pDeq->no_of_elements == 0 ? cstl_true : cstl_false;
}

int
cstl_deque_size(struct cstl_deque* pDeq) {
    if (pDeq == (struct cstl_deque*)0) {
        return cstl_true;
    }
    return pDeq->no_of_elements - 1;
}

cstl_error
cstl_deque_element_at(struct cstl_deque* pDeq, int index, void**elem) {
    cstl_error rc = CSTL_ERROR_SUCCESS;
    if (!pDeq) {
        return CSTL_DEQUE_NOT_INITIALIZED;
    }
    cstl_object_get_raw(pDeq->pElements[index], elem);
    return rc;
}

cstl_error
cstl_deque_delete(struct cstl_deque* pDeq) {
    int i = 0;

    if (pDeq == (struct cstl_deque*)0) {
        return CSTL_ERROR_SUCCESS;
    }
    if (pDeq->destruct_fn) {
        for (i = pDeq->head + 1; i < pDeq->tail; i++) {
            void* elem;
            if (cstl_deque_element_at(pDeq, i, &elem) == CSTL_ERROR_SUCCESS) {
                pDeq->destruct_fn(elem);
                free(elem);
            }
        }
    }
    for (i = pDeq->head + 1; i < pDeq->tail; i++) {
        cstl_object_delete(pDeq->pElements[i]);
    }
    free(pDeq->pElements);
    free(pDeq);

    return CSTL_ERROR_SUCCESS;
}

static struct cstl_object*
get_next_c_deque(struct cstl_iterator* pIterator) {
    struct cstl_deque *pDeq = (struct cstl_deque*)pIterator->pContainer;
    int index = ((struct cstl_iterator*)pIterator)->pCurrent;

    if (index < 0 || index >= pDeq->tail) {
        return (struct cstl_object*)0;
    }
    pIterator->pCurrentElement = pDeq->pElements[pIterator->pCurrent++];
    return pIterator->pCurrentElement;
}

static void*
get_value_c_deque(void* pObject) {
    void* elem = (void *)0;
    cstl_object_get_raw(pObject, &elem);
    return elem;
}

static void
replace_value_c_deque(struct cstl_iterator *pIterator, void* elem, size_t elem_size) {
    struct cstl_deque*  pDeq = (struct cstl_deque*)pIterator->pContainer;
    if (pDeq->destruct_fn) {
        void* old_element;
        if (cstl_object_get_raw(pIterator->pCurrentElement, &old_element) == CSTL_ERROR_SUCCESS) {
            pDeq->destruct_fn(old_element);
            free(old_element);
        }
    }
    cstl_object_replace_raw(pIterator->pCurrentElement, elem, elem_size);
}

struct cstl_iterator*
cstl_deque_new_iterator(struct cstl_deque* pDeq) {
    struct cstl_iterator *itr = (struct cstl_iterator*) calloc(1, sizeof(struct cstl_iterator));
    itr->get_next = get_next_c_deque;
    itr->get_value = get_value_c_deque;
    itr->replace_value = replace_value_c_deque;
    itr->pCurrent = pDeq->head + 1;
    itr->pContainer = pDeq;
    return itr;
}

void
cstl_deque_delete_iterator(struct cstl_iterator* pItr) {
    free(pItr);
}


// c_map.c
#include <stdio.h>

struct cstl_map*
cstl_map_new(cstl_compare fn_c_k, cstl_destroy fn_k_d, cstl_destroy fn_v_d) {
    struct cstl_map* pMap = (struct cstl_map*)calloc(1, sizeof(struct cstl_map));
    if (pMap == (struct cstl_map*)0) {
        return (struct cstl_map*)0;
    }
    pMap->root = cstl_rb_new(fn_c_k, fn_k_d, fn_v_d);
    if (pMap->root == (struct cstl_rb*)0) {
        return (struct cstl_map*)0;
    }
    return pMap;
}

cstl_error
cstl_map_insert(struct cstl_map* pMap, void* key, size_t key_size, void* value, size_t value_size) {
    if (pMap == (struct cstl_map*)0) {
        return CSTL_MAP_NOT_INITIALIZED;
    }
    return cstl_rb_insert(pMap->root, key, key_size, value, value_size);
}

cstl_bool
cstl_map_exists(struct cstl_map* pMap, void* key) {
    cstl_bool found = cstl_false;
    struct cstl_rb_node* node;

    if (pMap == (struct cstl_map*)0) {
        return cstl_false;
    }
    node = cstl_rb_find(pMap->root, key);
    if (node != (struct cstl_rb_node*)0) {
        return cstl_true;
    }
    return found;
}

cstl_error
cstl_map_remove(struct cstl_map* pMap, void* key) {
    cstl_error rc = CSTL_ERROR_SUCCESS;
    struct cstl_rb_node* node;
    if (pMap == (struct cstl_map*)0) {
        return CSTL_MAP_NOT_INITIALIZED;
    }
    node = cstl_rb_remove(pMap->root, key);
    if (node != (struct cstl_rb_node*)0) {
        void* removed_node = (void *)0;
        if (pMap->root->destruct_k_fn) {
            if (cstl_object_get_raw(node->key, &removed_node) == CSTL_ERROR_SUCCESS) {
                pMap->root->destruct_k_fn(removed_node);
                free(removed_node);
            }
        }
        cstl_object_delete(node->key);

        if (pMap->root->destruct_v_fn) {
            if (cstl_object_get_raw(node->value, &removed_node) == CSTL_ERROR_SUCCESS) {
                pMap->root->destruct_v_fn(removed_node);
                free(removed_node);
            }
        }
        cstl_object_delete(node->value);

        free(node);
    }
    return rc;
}

cstl_bool
cstl_map_find(struct cstl_map* pMap, void* key, void**value) {
    struct cstl_rb_node* node;

    if (pMap == (struct cstl_map*)0) {
        return cstl_false;
    }
    node = cstl_rb_find(pMap->root, key);
    if (node == (struct cstl_rb_node*)0) {
        return cstl_false;
    }
    cstl_object_get_raw(node->value, value);

    return cstl_true;
}

cstl_error
cstl_map_delete(struct cstl_map* x) {
    cstl_error rc = CSTL_ERROR_SUCCESS;
    if (x != (struct cstl_map*)0) {
        rc = cstl_rb_delete(x->root);
        free(x);
    }
    return rc;
}

static struct cstl_rb_node *
minimum_c_map(struct cstl_map *x) {
    return cstl_rb_minimum(x->root, x->root->root);
}

static struct cstl_object*
get_next_c_map(struct cstl_iterator* pIterator) {
    if (!pIterator->pCurrentElement) {
        pIterator->pCurrentElement = minimum_c_map(pIterator->pContainer);
    } else {
        struct cstl_map *x = (struct cstl_map*)pIterator->pContainer;
        pIterator->pCurrentElement = cstl_rb_tree_successor(x->root, pIterator->pCurrentElement);
    }
    if (!pIterator->pCurrentElement) {
        return (struct cstl_object*)0;
    }
    return ((struct cstl_rb_node*)pIterator->pCurrentElement)->value;
}

static void*
get_value_c_map(void* pObject) {
    void* elem = (void *)0;
    cstl_object_get_raw(pObject, &elem);
    return elem;
}

static void
replace_value_c_map(struct cstl_iterator *pIterator, void* elem, size_t elem_size) {
    struct cstl_map *pMap = (struct cstl_map*)pIterator->pContainer;

    if (pMap->root->destruct_v_fn) {
        void* old_element;
        if (cstl_object_get_raw(pIterator->pCurrentElement, &old_element) == CSTL_ERROR_SUCCESS) {
            pMap->root->destruct_v_fn(old_element);
            free(old_element);
        }
    }
    cstl_object_replace_raw(((struct cstl_rb_node*)pIterator->pCurrentElement)->value, elem, elem_size);
}

struct cstl_iterator*
cstl_map_new_iterator(struct cstl_map* pMap) {
    struct cstl_iterator *itr = (struct cstl_iterator*)calloc(1, sizeof(struct cstl_iterator));
    itr->get_next = get_next_c_map;
    itr->get_value = get_value_c_map;
    itr->replace_value = replace_value_c_map;
    itr->pContainer = pMap;
    itr->pCurrent = 0;
    itr->pCurrentElement = (void*)0;
    return itr;
}

void
cstl_map_delete_iterator(struct cstl_iterator* pItr) {
    free(pItr);
}


// c_rb.c
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define rb_sentinel &pTree->sentinel

static void debug_verify_properties(struct cstl_rb*);
static void debug_verify_property_1(struct cstl_rb*, struct cstl_rb_node*);
static void debug_verify_property_2(struct cstl_rb*, struct cstl_rb_node*);
static int debug_node_color(struct cstl_rb*, struct cstl_rb_node* n);
static void debug_verify_property_4(struct cstl_rb*, struct cstl_rb_node*);
static void debug_verify_property_5(struct cstl_rb*, struct cstl_rb_node*);
static void debug_verify_property_5_helper(struct cstl_rb*, struct cstl_rb_node*, int, int*);

static void
__left_rotate(struct cstl_rb* pTree, struct cstl_rb_node* x) {
    struct cstl_rb_node* y;
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

static void
__right_rotate(struct cstl_rb* pTree, struct cstl_rb_node* x) {
    struct cstl_rb_node* y = x->left;
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

struct cstl_rb*
cstl_rb_new(cstl_compare fn_c, cstl_destroy fn_ed, cstl_destroy fn_vd) {
    struct cstl_rb* pTree = (struct cstl_rb*)calloc(1, sizeof(struct cstl_rb));
    if (pTree == (struct cstl_rb*)0) {
        return (struct cstl_rb*)0;
    }
    pTree->compare_fn = fn_c;
    pTree->destruct_k_fn = fn_ed;
    pTree->destruct_v_fn = fn_vd;
    pTree->root = rb_sentinel;
    pTree->sentinel.left = rb_sentinel;
    pTree->sentinel.right = rb_sentinel;
    pTree->sentinel.parent = (struct cstl_rb_node*)0;
    pTree->sentinel.color = cstl_black;

    return pTree;
}

static void
__rb_insert_fixup(struct cstl_rb* pTree, struct cstl_rb_node* x) {
    while (x != pTree->root && x->parent->color == cstl_red) {
        if (x->parent == x->parent->parent->left) {
            struct cstl_rb_node* y = x->parent->parent->right;
            if (y->color == cstl_red) {
                x->parent->color = cstl_black;
                y->color = cstl_black;
                x->parent->parent->color = cstl_red;
                x = x->parent->parent;
            } else {
                if (x == x->parent->right) {
                    x = x->parent;
                    __left_rotate(pTree, x);
                }
                x->parent->color = cstl_black;
                x->parent->parent->color = cstl_red;
                __right_rotate(pTree, x->parent->parent);
            }
        } else {
            struct cstl_rb_node* y = x->parent->parent->left;
            if (y->color == cstl_red) {
                x->parent->color = cstl_black;
                y->color = cstl_black;
                x->parent->parent->color = cstl_red;
                x = x->parent->parent;
            } else {
                if (x == x->parent->left) {
                    x = x->parent;
                    __right_rotate(pTree, x);
                }
                x->parent->color = cstl_black;
                x->parent->parent->color = cstl_red;
                __left_rotate(pTree, x->parent->parent);
            }
        }
    }
    pTree->root->color = cstl_black;
}

struct cstl_rb_node*
cstl_rb_find(struct cstl_rb* pTree, void* key) {
    struct cstl_rb_node* x = pTree->root;

    while (x != rb_sentinel) {
        int c = 0;
        void* cur_key = (void *)0;
        cstl_object_get_raw(x->key, &cur_key);
        c = pTree->compare_fn(key, cur_key);
        free(cur_key);
        if (c == 0) {
            break;
        } else {
            x = c < 0 ? x->left : x->right;
        }
    }
    if (x == rb_sentinel) {
        return (struct cstl_rb_node*)0;
    }
    return x;
}

cstl_error
cstl_rb_insert(struct cstl_rb* pTree, void* k, size_t key_size, void* v, size_t value_size) {
    cstl_error rc = CSTL_ERROR_SUCCESS;
    struct cstl_rb_node* x;
    struct cstl_rb_node* y;
    struct cstl_rb_node* z;

    x = (struct cstl_rb_node*)calloc(1, sizeof(struct cstl_rb_node));
    if (x == (struct cstl_rb_node*)0) {
        return CSTL_ERROR_MEMORY;
    }
    x->left = rb_sentinel;
    x->right = rb_sentinel;
    x->color = cstl_red;

    x->key = cstl_object_new(k, key_size);
    if (v) {
        x->value = cstl_object_new(v, value_size);
    } else {
        x->value = (struct cstl_object*)0;
    }

    y = pTree->root;
    z = (struct cstl_rb_node*)0;

    while (y != rb_sentinel) {
        int c = 0;
        void* cur_key;
        void* new_key;

        cstl_object_get_raw(y->key, &cur_key);
        cstl_object_get_raw(x->key, &new_key);

        c = (pTree->compare_fn) (new_key, cur_key);
        free(cur_key);
        free(new_key);
        if (c == 0) {
            /* TODO : Delete node here */
            return CSTL_RBTREE_KEY_DUPLICATE;
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
        cstl_object_get_raw(z->key, &cur_key);
        cstl_object_get_raw(x->key, &new_key);

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

static void
__rb_remove_fixup(struct cstl_rb* pTree, struct cstl_rb_node* x) {
    while (x != pTree->root && x->color == cstl_black) {
        if (x == x->parent->left) {
            struct cstl_rb_node* w = x->parent->right;
            if (w->color == cstl_red) {
                w->color = cstl_black;
                x->parent->color = cstl_red;
                __left_rotate(pTree, x->parent);
                w = x->parent->right;
            }
            if (w->left->color == cstl_black && w->right->color == cstl_black) {
                w->color = cstl_red;
                x = x->parent;
            } else {
                if (w->right->color == cstl_black) {
                    w->left->color = cstl_black;
                    w->color = cstl_red;
                    __right_rotate(pTree, w);
                    w = x->parent->right;
                }
                w->color = x->parent->color;
                x->parent->color = cstl_black;
                w->right->color = cstl_black;
                __left_rotate(pTree, x->parent);
                x = pTree->root;
            }
        } else {
            struct cstl_rb_node* w = x->parent->left;
            if (w->color == cstl_red) {
                w->color = cstl_black;
                x->parent->color = cstl_red;
                __right_rotate(pTree, x->parent);
                w = x->parent->left;
            }
            if (w->right->color == cstl_black && w->left->color == cstl_black) {
                w->color = cstl_red;
                x = x->parent;
            } else {
                if (w->left->color == cstl_black) {
                    w->right->color = cstl_black;
                    w->color = cstl_red;
                    __left_rotate(pTree, w);
                    w = x->parent->left;
                }
                w->color = x->parent->color;
                x->parent->color = cstl_black;
                w->left->color = cstl_black;
                __right_rotate(pTree, x->parent);
                x = pTree->root;
            }
        }
    }
    x->color = cstl_black;
}

static struct cstl_rb_node*
__remove_c_rb(struct cstl_rb* pTree, struct cstl_rb_node* z) {
    struct cstl_rb_node* x = (struct cstl_rb_node*)0;
    struct cstl_rb_node* y = (struct cstl_rb_node*)0;

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
        struct cstl_object* tmp;
        tmp = z->key;
        z->key = y->key;
        y->key = tmp;

        tmp = z->value;
        z->value = y->value;
        y->value = tmp;
    }
    if (y->color == cstl_black) {
        __rb_remove_fixup(pTree, x);
    }
    debug_verify_properties(pTree);
    return y;
}

struct cstl_rb_node*
    cstl_rb_remove(struct cstl_rb* pTree, void* key) {
    struct cstl_rb_node* z = (struct cstl_rb_node*)0;

    z = pTree->root;
    while (z != rb_sentinel) {
        int c = 0;
        void* cur_key;
        cstl_object_get_raw(z->key, &cur_key);
        c = pTree->compare_fn(key, cur_key);
        free(cur_key);
        if (c == 0) {
            break;
        } else {
            z = (c < 0) ? z->left : z->right;
        }
    }
    if (z == rb_sentinel) {
        return (struct cstl_rb_node*)0;
    }
    return __remove_c_rb(pTree, z);
}

static void
__delete_c_rb_node(struct cstl_rb* pTree, struct cstl_rb_node* x) {
    void* key;
    void* value;

    if (pTree->destruct_k_fn) {
        cstl_object_get_raw(x->key, &key);
        pTree->destruct_k_fn(key);
        free(key);
    }
    cstl_object_delete(x->key);

    if (x->value) {
        if (pTree->destruct_v_fn) {
            cstl_object_get_raw(x->value, &value);
            pTree->destruct_v_fn(value);
            free(value);
        }
        cstl_object_delete(x->value);
    }
}

cstl_error
cstl_rb_delete(struct cstl_rb* pTree) {
    cstl_error rc = CSTL_ERROR_SUCCESS;
    struct cstl_rb_node* z = pTree->root;

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

struct cstl_rb_node *
cstl_rb_minimum(struct cstl_rb* pTree, struct cstl_rb_node* x) {
    while (x->left != rb_sentinel) {
        x = x->left;
    }
    return x;
}

struct cstl_rb_node *
maximum_cstl_rb(struct cstl_rb* pTree, struct cstl_rb_node* x) {
    while (x->right != rb_sentinel) {
        x = x->right;
    }
    return x;
}

cstl_bool
cstl_rb_empty(struct cstl_rb* pTree) {
    if (pTree->root != rb_sentinel) {
        return cstl_true;
    }
    return cstl_false;
}

struct cstl_rb_node*
cstl_rb_tree_successor(struct cstl_rb* pTree, struct cstl_rb_node* x) {
    struct cstl_rb_node *y = (struct cstl_rb_node*)0;
    if (x->right != rb_sentinel) {
        return cstl_rb_minimum(pTree, x->right);
    }
    if (x == maximum_cstl_rb(pTree, pTree->root)) {
        return (struct cstl_rb_node*)0;
    }
    y = x->parent;
    while (y != rb_sentinel && x == y->right) {
        x = y;
        y = y->parent;
    }
    return y;
}

/*
struct cstl_rb_node *
get_next_c_rb(struct cstl_rb* pTree, struct cstl_rb_node**current, struct cstl_rb_node**pre) {
    struct cstl_rb_node* prev_current;
    while ((*current) != rb_sentinel) {
        if ((*current)->left == rb_sentinel) {
            prev_current = (*current);
            (*current) = (*current)->right;
            return prev_current->raw_data.key;
        } else {
            (*pre) = (*current)->left;
            while ((*pre)->right != rb_sentinel && (*pre)->right != (*current))
                (*pre) = (*pre)->right;
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
    return (struct cstl_rb_node*)0;
} */

void debug_verify_properties(struct cstl_rb* t) {
    debug_verify_property_1(t, t->root);
    debug_verify_property_2(t, t->root);
    debug_verify_property_4(t, t->root);
    debug_verify_property_5(t, t->root);
}

void debug_verify_property_1(struct cstl_rb* pTree, struct cstl_rb_node* n) {
    assert(debug_node_color(pTree, n) == cstl_red || debug_node_color(pTree, n) == cstl_black);
    if (n == rb_sentinel) { return; }
    debug_verify_property_1(pTree, n->left);
    debug_verify_property_1(pTree, n->right);
}

void debug_verify_property_2(struct cstl_rb* pTree, struct cstl_rb_node* root) {
    assert(debug_node_color(pTree, root) == cstl_black);
}

int debug_node_color(struct cstl_rb* pTree, struct cstl_rb_node* n) {
    return n == rb_sentinel ? cstl_black : n->color;
}

void debug_verify_property_4(struct cstl_rb* pTree, struct cstl_rb_node* n) {
    if (debug_node_color(pTree, n) == cstl_red) {
        assert(debug_node_color(pTree, n->left) == cstl_black);
        assert(debug_node_color(pTree, n->right) == cstl_black);
        assert(debug_node_color(pTree, n->parent) == cstl_black);
    }
    if (n == rb_sentinel) { return; }
    debug_verify_property_4(pTree, n->left);
    debug_verify_property_4(pTree, n->right);
}

void debug_verify_property_5(struct cstl_rb* pTree, struct cstl_rb_node* root) {
    int black_count_path = -1;
    debug_verify_property_5_helper(pTree, root, 0, &black_count_path);
}

void debug_verify_property_5_helper(struct cstl_rb* pTree, struct cstl_rb_node* n, int black_count, int* path_black_count) {
    if (debug_node_color(pTree, n) == cstl_black) {
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


// c_set.c
#include <stdio.h>

struct cstl_set*
cstl_set_new(cstl_compare fn_c, cstl_destroy fn_d) {
    struct cstl_set* pSet = (struct cstl_set*)calloc(1, sizeof(struct cstl_set));
    if (pSet == (struct cstl_set*)0) {
        return (struct cstl_set*)0;
    }
    pSet->root = cstl_rb_new(fn_c, fn_d, (void*)0);
    if (pSet->root == (struct cstl_rb*)0) {
        return (struct cstl_set*)0;
    }
    return pSet;
}

cstl_error
cstl_set_insert(struct cstl_set* pSet, void* key, size_t key_size) {
    if (pSet == (struct cstl_set*)0) {
        return CSTL_SET_NOT_INITIALIZED;
    }
    return cstl_rb_insert(pSet->root, key, key_size, (void*)0, 0);
}

cstl_bool
cstl_set_exists(struct cstl_set* pSet, void* key) {
    cstl_bool found = cstl_false;
    struct cstl_rb_node* node;

    if (pSet == (struct cstl_set*)0) {
        return cstl_false;
    }
    node = cstl_rb_find(pSet->root, key);
    if (node != (struct cstl_rb_node*)0) {
        return cstl_true;
    }
    return found;
}

cstl_error
cstl_set_remove(struct cstl_set* pSet, void* key) {
    cstl_error rc = CSTL_ERROR_SUCCESS;
    struct cstl_rb_node* node;
    if (pSet == (struct cstl_set*)0) {
        return CSTL_SET_NOT_INITIALIZED;
    }
    node = cstl_rb_remove(pSet->root, key);
    if (node != (struct cstl_rb_node*)0) {
        if (pSet->root->destruct_k_fn) {
            void* key = (void*)0;
            if (CSTL_ERROR_SUCCESS == cstl_object_get_raw(node->key, &key)) {
                pSet->root->destruct_k_fn(key);
                free(key);
            }
        }
        cstl_object_delete(node->key);

        free(node);
    }
    return rc;
}

cstl_bool
cstl_set_find(struct cstl_set* pSet, void* key, void* outKey) {
    struct cstl_rb_node* node;

    if (pSet == (struct cstl_set*)0) {
        return cstl_false;
    }
    node = cstl_rb_find(pSet->root, key);
    if (node == (struct cstl_rb_node*)0) {
        return cstl_false;
    }
    cstl_object_get_raw(node->key, outKey);

    return cstl_true;
}

cstl_error
cstl_set_delete(struct cstl_set* x) {
    cstl_error rc = CSTL_ERROR_SUCCESS;
    if (x != (struct cstl_set*)0) {
        rc = cstl_rb_delete(x->root);
        free(x);
    }
    return rc;
}

static struct cstl_rb_node *
minimum_c_set(struct cstl_set *x) {
    return cstl_rb_minimum(x->root, x->root->root);
}

static struct cstl_object*
get_next_c_set(struct cstl_iterator* pIterator) {
    if (!pIterator->pCurrentElement) {
        pIterator->pCurrentElement = minimum_c_set(pIterator->pContainer);
    } else {
        struct cstl_set *x = (struct cstl_set*)pIterator->pContainer;
        pIterator->pCurrentElement = cstl_rb_tree_successor(x->root, pIterator->pCurrentElement);
    }
    if (!pIterator->pCurrentElement) {
        return (struct cstl_object*)0;
    }
    return ((struct cstl_rb_node*)pIterator->pCurrentElement)->key;
}

static void*
get_value_c_set(void* pObject) {
    void* elem = (void *)0;
    cstl_object_get_raw(pObject, &elem);
    return elem;
}

struct cstl_iterator*
cstl_set_new_iterator(struct cstl_set* pSet) {
    struct cstl_iterator *itr = (struct cstl_iterator*) calloc(1, sizeof(struct cstl_iterator));
    itr->get_next = get_next_c_set;
    itr->get_value = get_value_c_set;
    itr->pContainer = pSet;
    itr->pCurrent = 0;
    itr->pCurrentElement = (void*)0;
    return itr;
}

void
cstl_set_delete_iterator(struct cstl_iterator* pItr) {
    free(pItr);
}


// c_slist.c
struct cstl_slist*
cstl_slist_new(cstl_destroy fn_d, cstl_compare fn_c) {
    struct cstl_slist* pSlist = (struct cstl_slist*)calloc(1, sizeof(struct cstl_slist));
    pSlist->head = (struct cstl_slist_node*)0;
    pSlist->destruct_fn = fn_d;
    pSlist->compare_key_fn = fn_c;
    pSlist->size = 0;
    return pSlist;
}

void
cstl_slist_delete(struct cstl_slist* pSlist) {
    while (pSlist->size != 0) {
        cstl_slist_remove(pSlist, 0);
    }
    free(pSlist);
}

cstl_error
cstl_slist_push_back(struct cstl_slist* pSlist, void* elem, size_t elem_size) {

    struct cstl_slist_node* current = (struct cstl_slist_node*)0;
    struct cstl_slist_node* new_node = (struct cstl_slist_node*)0;

    new_node = (struct cstl_slist_node*)calloc(1, sizeof(struct cstl_slist_node));

    new_node->elem = cstl_object_new(elem, elem_size);
    if (!new_node->elem) {
        return CSTL_SLIST_INSERT_FAILED;
    }
    new_node->next = (struct cstl_slist_node*)0;

    if (pSlist->head == (struct cstl_slist_node*)0) {
        pSlist->head = new_node;
        pSlist->size++;
        return CSTL_ERROR_SUCCESS;
    }
    current = pSlist->head;
    while (current->next != (struct cstl_slist_node*)0) {
        current = current->next;
    }
    current->next = new_node;
    pSlist->size++;

    return CSTL_ERROR_SUCCESS;
}

static void
__remove_c_list(struct cstl_slist* pSlist, struct cstl_slist_node* pSlistNode) {
    if (pSlist->destruct_fn) {
        void* elem;
        if (cstl_object_get_raw(pSlistNode->elem, &elem) == CSTL_ERROR_SUCCESS) {
            pSlist->destruct_fn(elem);
            free(elem);
        }
    }
    cstl_object_delete(pSlistNode->elem);

    free(pSlistNode);
}

void
cstl_slist_remove(struct cstl_slist* pSlist, int pos) {
    int i = 0;

    struct cstl_slist_node* current = pSlist->head;
    struct cstl_slist_node* temp = (struct cstl_slist_node*)0;

    if (pos > pSlist->size) { return; }

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

cstl_error
cstl_slist_insert(struct cstl_slist* pSlist, int pos, void* elem, size_t elem_size) {
    int i = 0;
    struct cstl_slist_node* current = pSlist->head;
    struct cstl_slist_node* new_node = (struct cstl_slist_node*)0;

    if (pos == 1) {
        new_node = (struct cstl_slist_node*)calloc(1, sizeof(struct cstl_slist_node));
        new_node->elem = cstl_object_new(elem, elem_size);
        if (!new_node->elem) {
            free(new_node);
            return CSTL_SLIST_INSERT_FAILED;
        }
        new_node->next = pSlist->head;
        pSlist->head = new_node;
        pSlist->size++;
        return CSTL_ERROR_SUCCESS;
    }

    if (pos >= pSlist->size + 1) {
        return cstl_slist_push_back(pSlist, elem, elem_size);
    }

    for (i = 1; i < pos - 1; i++) {
        current = current->next;
    }
    new_node = (struct cstl_slist_node*)calloc(1, sizeof(struct cstl_slist_node));
    new_node->elem = cstl_object_new(elem, elem_size);
    if (!new_node->elem) {
        free(new_node);
        return CSTL_SLIST_INSERT_FAILED;
    }

    new_node->next = current->next;
    current->next = new_node;
    pSlist->size++;

    return CSTL_ERROR_SUCCESS;
}

void
cstl_slist_for_each(struct cstl_slist* pSlist, void(*fn)(void*)) {
    void* elem;
    struct cstl_slist_node* current = pSlist->head;
    while (current != (struct cstl_slist_node*)0) {
        cstl_object_get_raw(current->elem, &elem);
        (fn)(elem);
        free(elem);
        current = current->next;
    }
}

cstl_bool
cstl_slist_find(struct cstl_slist* pSlist, void* find_value, void**out_value) {
    struct cstl_slist_node* current = pSlist->head;
    while (current != (struct cstl_slist_node*)0) {
        cstl_object_get_raw(current->elem, out_value);
        if ((pSlist->compare_key_fn)(find_value, *out_value) != 0) {
            break;
        }
        free(*out_value);
        current = current->next;
    }
    if (current) {
        return cstl_true;
    }
    return cstl_false;
}

static struct cstl_object*
get_next_c_slist(struct cstl_iterator* pIterator) {
    struct cstl_slist *pSlist = (struct cstl_slist*)pIterator->pContainer;
    if (!pIterator->pCurrentElement) {
        pIterator->pCurrentElement = (struct cstl_slist_node*)pSlist->head;
    } else {
        pIterator->pCurrentElement = ((struct cstl_slist_node*)pIterator->pCurrentElement)->next;
    }
    if (!pIterator->pCurrentElement) {
        return (struct cstl_object*)0;
    }
    return ((struct cstl_slist_node*)pIterator->pCurrentElement)->elem;
}

static void*
get_value_c_slist(void* pObject) {
    void* elem;
    cstl_object_get_raw(pObject, &elem);
    return elem;
}

static void
replace_value_c_slist(struct cstl_iterator *pIterator, void* elem, size_t elem_size) {
    struct cstl_slist*  pSlist = (struct cstl_slist*)pIterator->pContainer;
    struct cstl_object *pObj = ((struct cstl_slist_node*)pIterator->pCurrentElement)->elem;

    if (pSlist->destruct_fn) {
        void* old_element;
        if (cstl_object_get_raw(pObj, &old_element) == CSTL_ERROR_SUCCESS) {
            pSlist->destruct_fn(old_element);
            free(old_element);
        }
    }
    cstl_object_replace_raw(pObj, elem, elem_size);
}

struct cstl_iterator*
cstl_slist_new_iterator(struct cstl_slist* pSlist) {
    struct cstl_iterator *itr = (struct cstl_iterator*) calloc(1, sizeof(struct cstl_iterator));
    itr->get_next = get_next_c_slist;
    itr->get_value = get_value_c_slist;
    itr->replace_value = replace_value_c_slist;
    itr->pContainer = pSlist;
    itr->pCurrentElement = (void*)0;
    itr->pCurrent = 0;
    return itr;
}

void
cstl_slist_delete_iterator(struct cstl_iterator* pItr) {
    free(pItr);
}


// c_util.c
#include <string.h>
#include <stdlib.h>

void
cstl_copy(void* destination, void* source, size_t size) {
    memcpy((char*)destination, source, size);
}

void
cstl_get(void* destination, void* source, size_t size) {
    memcpy(destination, (char*)source, size);
}

struct cstl_object*
cstl_object_new(void* inObject, size_t obj_size) {
    struct cstl_object* tmp = (struct cstl_object*)calloc(1, sizeof(struct cstl_object));
    if (!tmp) {
        return (struct cstl_object*)0;
    }
    tmp->size = obj_size;
    tmp->raw_data = (void*)calloc(obj_size, sizeof(char));
    if (!tmp->raw_data) {
        free(tmp);
        return (struct cstl_object*)0;
    }
    memcpy(tmp->raw_data, inObject, obj_size);
    return tmp;
}

cstl_error
cstl_object_get_raw(struct cstl_object *inObject, void**elem) {
    *elem = (void*)calloc(inObject->size, sizeof(char));
    if (!*elem) {
        return CSTL_ELEMENT_RETURN_ERROR;
    }
    memcpy(*elem, inObject->raw_data, inObject->size);

    return CSTL_ERROR_SUCCESS;
}

void
cstl_object_replace_raw(struct cstl_object* current_object, void* elem, size_t elem_size) {
    free(current_object->raw_data);
    current_object->raw_data = (void*)calloc(elem_size, sizeof(char));
    memcpy(current_object->raw_data, elem, elem_size);
}

void
cstl_object_delete(struct cstl_object* inObject) {
    if (inObject) {
        free(inObject->raw_data);
        free(inObject);
    }
}

char*
cstl_strdup(char *ptr) {
#ifdef WIN32
    return _strdup(ptr);
#else
    return strdup(ptr);
#endif
}
