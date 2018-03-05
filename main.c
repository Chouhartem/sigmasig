/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2017 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * RELIC is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with RELIC. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>

#include <relic.h>
#include <relic_bench.h>
#include "sigmasig.h"
#define NBENCH 100

static void sig_eff_protocols(void)
{
  sep_pk_t pk = malloc(sizeof(struct sep_pk_t));
  sep_sk_t sk;
  bn_null(sk);
  bn_new(sk);
  /* m */
  bn_t m;
  bn_null(m);
  /* σ */
  sep_sign_t sigma;
  sigma = malloc(sizeof(struct sep_sign_t));
  sep_sign_init(sigma);

  sep_pk_init(pk);
  sep_keygen(pk, sk);
  bn_rand_mod(m, pk->p);
  sep_sign(sigma, sk, pk, m);
  //sep_sign_print(sigma);

  //printf("%d\n",sep_verif(sigma, pk, m));

  sep_pk_free(pk);
  sep_sign_free(sigma);
  bn_free(sk);
  bn_free(m);
}

static void group_sig(void)
{
  int i;
  gs_pp_t pp            = malloc(sizeof(struct gs_pp_t));
  gs_sgm_t sgm;
  gs_soa_t soa          = malloc(sizeof(struct gs_soa_t));
  gs_cert_t* cert       = malloc(NBENCH * sizeof *cert);
  gs_sec_t sec[NBENCH];
  gs_trans_t* trans     = malloc(NBENCH * sizeof *trans);
  msg_t msg             = malloc(sizeof(struct msg_t));
  gs_sig_t* sig          = malloc(NBENCH * sizeof *sig);

  gs_pp_init(pp);
  bn_null(sgm); bn_new(sgm);
  gs_soa_init(soa);

  BENCH_ONCE("gs_keygen", gs_keygen(pp, sgm, soa));

  for (i = 0; i < NBENCH; ++i) {
    cert[i] = malloc(sizeof *cert[i]);
    gs_cert_init (cert[i]);
    bn_null(sec[i]); bn_new(sec[i]);
    bn_zero(sec[i]);
    trans[i] = malloc(sizeof *trans[i]);
    gs_trans_init(trans[i]);
  }
  BENCH_SMALL("gs_join", gs_join(cert[i], sec[i], trans[i], pp, sgm));

  msg_init_set(msg, "Bonjour");
  for (i = 0; i < NBENCH; ++i) {
    sig[i] = malloc(sizeof *sig[i]);
    gs_sig_init(sig[i]);
  }
  BENCH_SMALL("gs_sign", gs_sign(sig[i], pp, sec[i], cert[i], msg));

  BENCH_SMALL("gs_verif", gs_verif(pp, msg, sig[i]));

  /* Close */
  gs_pp_free(pp);
  bn_free(sgm);
  gs_soa_free(soa);
  for(i = 0; i < NBENCH; ++i) {
    gs_cert_free(cert[i]);
    bn_free(sec[i]);
    gs_trans_free(trans[i]);
    gs_sig_free(sig[i]);
  }
  free(cert);
  free(trans);
  free(sig);
  msg_free(msg);
}

int main (void)
{
  if (core_init() != STS_OK) {
    core_clean();
    return 1;
  }

  conf_print();

	if (pc_param_set_any() == STS_OK) {
    sig_eff_protocols();
    group_sig();
  } else
    THROW(ERR_NO_CURVE);

  return 0;
}

