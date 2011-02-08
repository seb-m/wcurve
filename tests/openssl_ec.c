/*
  openssl_ec.c - EC reference implementation based on OpenSSL
  Copyright (c) 2011 Sebastien Martini <seb@dbzteam.org>

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/

// Used as reference implementation when testing wcurve. This implementation
// is based on OpenSSL. See wcurve_unittest.py. Raise openssl_ec.ECError on
// errors.
//
// Example:
//
// import openssl_ec
// try:
//    rx, ry = openssl_ec.mul(curve_name,
//                            (scalar_a, point_a_x, point_a_y),
//                            (scalar_b, point_b_x, point_b_y))
// except openssl_ec.ECError as err:
//    print(err)
//

#include <Python.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/objects.h>

// Python exception
static PyObject *ECError;

static int _scalar_mul(const char *curve_name, BIGNUM *bn[], const int ops,
                       char **resx, char **resy) {
  EC_GROUP *group = NULL;
  EC_POINT *point_res = NULL;
  EC_POINT *points[ops];
  const BIGNUM *scalars[ops];
  BIGNUM *bn_x = NULL;
  BIGNUM *bn_y = NULL;
  int ret = 0;
  int i = 0;

  for (i = 0; i < ops; ++i) {
    points[i] = NULL;
    scalars[i] = NULL;
  }

  group = EC_GROUP_new_by_curve_name(OBJ_txt2nid(curve_name));
  if (group == NULL) {
    PyErr_SetString(ECError, ERR_reason_error_string(ERR_get_error()));
    return -1;
  }

  for (i = 0; i < ops; ++i) {
    scalars[i] = bn[3 * i];

    points[i] = EC_POINT_new(group);
    if (points[i] == NULL) {
      PyErr_SetString(ECError, ERR_reason_error_string(ERR_get_error()));
      goto err;
    }

    ret = EC_POINT_set_affine_coordinates_GFp(group, points[i], bn[3 * i + 1],
                                              bn[3 * i + 2], NULL);
    if (ret != 1) {
      PyErr_SetString(ECError, ERR_reason_error_string(ERR_get_error()));
      goto err;
    }

    ret = EC_POINT_is_on_curve(group, points[i], NULL);
    if (ret != 1) {
      PyErr_SetString(ECError, "Point is not on curve");
      goto err;
    }
  }

  point_res = EC_POINT_new(group);
  if (point_res == NULL) {
    PyErr_SetString(ECError, ERR_reason_error_string(ERR_get_error()));
    goto err;
  }

  ret = EC_POINTs_mul(group, point_res, NULL, ops, (const EC_POINT**) points,
                      scalars, NULL);
  if (ret != 1) {
    PyErr_SetString(ECError, ERR_reason_error_string(ERR_get_error()));
    goto err;
  }

  bn_x = BN_new();
  bn_y = BN_new();
  if (bn_x == NULL || bn_y == NULL) {
    PyErr_SetString(ECError, ERR_reason_error_string(ERR_get_error()));
    goto err;
  }

  ret = EC_POINT_get_affine_coordinates_GFp(group, point_res, bn_x, bn_y,
                                            NULL);
  if (ret != 1) {
    PyErr_SetString(ECError, ERR_reason_error_string(ERR_get_error()));
    goto err;
  }

  *resx = BN_bn2hex(bn_x);
  *resy = BN_bn2hex(bn_y);

  ret = 0;
  goto end;

err:
  ret = -1;

end:
  for (i = 0; i < ops; ++i)
    if (points[i] != NULL)
      EC_POINT_clear_free(points[i]);

  EC_GROUP_free(group);

  if (bn_x != NULL)
    BN_free(bn_x);

  if (bn_y != NULL)
    BN_free(bn_y);

  return ret;
}

static PyObject* mul(PyObject* self, PyObject* args) {
  BIGNUM *bn[6];
  int ret = -1;
  int ops = 1;
  int i;

  char *curve_name = NULL;

  char *sa = NULL;
  char *xa = NULL;
  char *ya = NULL;

  char *sb = NULL;
  char *xb = NULL;
  char *yb = NULL;

  char *resx = NULL;
  char *resy = NULL;

  for (i = 0; i < 6; ++i)
    bn[i] = NULL;

  if(!PyArg_ParseTuple(args, "s(sss)|(sss)", &curve_name, &sa, &xa, &ya, &sb,
                       &xb, &yb))
    return NULL;

  ERR_load_crypto_strings();

  if (BN_hex2bn(&(bn[0]), sa) == 0)
    goto end;
  if (BN_hex2bn(&(bn[1]), xa) == 0)
    goto end;
  if (BN_hex2bn(&(bn[2]), ya) == 0)
    goto end;

  if (sb != NULL && xb != NULL && yb != NULL) {
    ops = 2;

    if (BN_hex2bn(&(bn[3]), sb) == 0)
      goto end;
    if (BN_hex2bn(&(bn[4]), xb) == 0)
      goto end;
    if (BN_hex2bn(&(bn[5]), yb) == 0)
      goto end;
  }

  ret = _scalar_mul(curve_name, bn, ops, &resx, &resy);

end:
  ERR_free_strings();

  for (i = 0; i < 6; ++i)
    BN_clear_free(bn[i]);

  if (ret == 0)
    return Py_BuildValue("(ss)", resx, resy);
  return NULL;
}

static PyMethodDef openssl_ec_methods[] = {
  {"mul", mul, METH_VARARGS, "Scalar multiplication"},
  {0}
};

/* python 2 */
#if PY_VERSION_HEX < 0x03000000

void initopenssl_ec(void) {
  PyObject *m;

  m = Py_InitModule3("openssl_ec", openssl_ec_methods, "module openssl_ec");
  if (m == NULL)
    return;

  ECError = PyErr_NewException("openssl_ec.ECError", NULL, NULL);
  Py_INCREF(ECError);
  PyModule_AddObject(m, "ECError", ECError);
}

#else  /* python 3 */

static struct PyModuleDef openssl_ecmodule = {
  {}, /* m_base */
  "openssl_ec",  /* m_name */
  "module openssl_ec",  /* m_doc */
  0,  /* m_size */
  openssl_ec_methods,  /* m_methods */
  0,  /* m_reload */
  0,  /* m_traverse */
  0,  /* m_clear */
  0,  /* m_free */
};

PyObject* PyInit_openssl_ec(void) {
  PyObject *m;

  m = PyModule_Create(&openssl_ecmodule);
  if (m == NULL)
    return NULL;

  ECError = PyErr_NewException("openssl_ec.ECError", NULL, NULL);
  Py_INCREF(ECError);
  PyModule_AddObject(m, "ECError", ECError);

  return m;
}

#endif  /* PY_VERSION_HEX */
