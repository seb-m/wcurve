/*
  ec_ref.c - ec ref implementation
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
// is based on OpenSSL. See wcurve_unittest.py.
//
// $ gcc -W -Wall -o ec_ref ec_ref.c -lcrypto
// $ ./ec_ref prime256v1 scalar x y [scalar x y]
//
#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/objects.h>


static int run_ref(const char *curve_name, BIGNUM *args[], const int num) {
  EC_GROUP *group = NULL;
  EC_POINT *point_res = NULL;
  EC_POINT *points[num];
  const BIGNUM *scalars[num];
  BIGNUM *res_x = NULL;
  BIGNUM *res_y = NULL;
  int ret = 0;
  int i = 0;

  group = EC_GROUP_new_by_curve_name(OBJ_txt2nid(curve_name));
  if (group == NULL) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  for (i = 0; i < num; ++i) {
    scalars[i] = args[3 * i];

    points[i] = EC_POINT_new(group);
    if (points[i] == NULL) {
      ERR_print_errors_fp(stderr);
      goto err;
    }

    ret = EC_POINT_set_affine_coordinates_GFp(group, points[i], args[3 * i + 1],
                                              args[3 * i + 2], NULL);
    if (ret != 1) {
      ERR_print_errors_fp(stderr);
      goto err;
    }

    ret = EC_POINT_is_on_curve(group, points[i], NULL);
    if (ret != 1) {
      fprintf(stderr, "Point is not on curve.\n");
      goto err;
    }
  }

  point_res = EC_POINT_new(group);
  if (point_res == NULL) {
    ERR_print_errors_fp(stderr);
    goto err;
  }

  ret = EC_POINTs_mul(group, point_res, NULL, num, (const EC_POINT**) points,
                      scalars, NULL);
  if (ret != 1) {
    ERR_print_errors_fp(stderr);
    goto err;
  }

  res_x = BN_new();
  res_y = BN_new();
  if (res_x == NULL || res_y == NULL) {
    ERR_print_errors_fp(stderr);
    goto err;
  }

  ret = EC_POINT_get_affine_coordinates_GFp(group, point_res, res_x, res_y,
                                            NULL);
  if (ret != 1) {
    ERR_print_errors_fp(stderr);
    goto err;
  }

  BN_print_fp(stdout, res_x);
  putc('\n', stdout);
  BN_print_fp(stdout, res_y);
  putc('\n', stdout);

  ret = 0;
  goto end;

err:
  ret = -1;

end:
  for (i = 0; i < num; ++i)
    if (points[i] != NULL)
      EC_POINT_free(points[i]);

  EC_GROUP_free(group);

  if (res_x != NULL)
    BN_free(res_x);

  if (res_y != NULL)
    BN_free(res_y);

  return ret;
}

int main(int argc, char *argv[]) {
  const int num = argc - 2;
  BIGNUM *args[num];
  int ret = -1;
  int i;

  if (argc < 5 || num % 3)
    return ret;

  ERR_load_crypto_strings();

  for (i = 0; i < num; ++i) {
    args[i] = BN_new();
    if (BN_hex2bn(&(args[i]), argv[i + 2]) == 0)
      return ret;
  }

  ret = run_ref(argv[1], args, num / 3);

  for (i = 0; i < num; ++i) {
    BN_free(args[i]);
  }

  ERR_free_strings();

  return ret;
}
