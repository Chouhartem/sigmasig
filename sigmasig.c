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

/**
 * @file
 *
 * Implementation of the Libert, Mouhartem, Peters, Yung'16 Group Signature scheme.
 *
 * @ingroup cp
 */

#include <relic.h>
#include <relic_test.h>
#include <relic_bench.h>
#include "sigmasig.h"
#include <assert.h>

/**********************/
/* Public Definitions */
/**********************/

/******************/
/* crs_t routines */
/******************/

void crs_init (crs_t t)
{
  int i;

  for (i = 0; i < 3; ++i) {
    g1_null(t->z[i]);
    g1_new (t->z[i]);
    g1_set_infty(t->z[i]);
  }

  g2_null(t->gz);
  g2_new (t->gz);
  g2_set_infty(t->gz);

  for (i = 0; i < 6; ++i) {
    g2_null(t->g2[i]);
    g2_new (t->g2[i]);
    g2_set_infty(t->g2[i]);
  }
}

void crs_free (crs_t t)
{
  int i;
  g2_free(t->gz);
  for (i = 0; i < 3; ++i)
    g1_free(t->z[i]);
  for (i = 0; i < 6; ++i)
    g2_free(t->g2[i]);
  free(t);
}

void crs_print(const crs_t t)
{
  int i;
  printf("***** Begin CRS *****\n");
  for(i = 0; i < 3; ++i) {
    printf("z_%d:\n", i+1);
    g1_print(t->z[i]);
  }
  printf("gz:\n");
  g2_print(t->gz);
  for(i = 0; i < 6; ++i) {
    printf("g2_%d:\n", i+1);
    g2_print(t->g2[i]);
  }
  printf("***** End CRS *****\n");
}

/**************************************/
/* Signature with efficient protocols */
/**************************************/

void sep_pk_init(sep_pk_t t)
{
  t->crs = malloc(sizeof *(t->crs));
  crs_init(t->crs);

  g1_null(t->g);
  g1_null(t->h);
  g1_null(t->v);
  g1_null(t->w);
  g1_null(t->Omega);
  g2_null(t->gh);
  bn_null(t->p);

  g1_new (t->g);
  g1_new (t->h);
  g1_new (t->v);
  g1_new (t->w);
  g1_new (t->Omega);
  g2_new (t->gh);
  bn_new (t->p);
}

void sep_pk_free(sep_pk_t t)
{
  crs_free(t->crs);

  g1_free(t->g);
  g1_free(t->h);
  g1_free(t->v);
  g1_free(t->w);
  g1_free(t->Omega);
  g2_free(t->gh);
  bn_free(t->p);
  free(t);
}

void sep_pk_print(const sep_pk_t t)
{
  printf("***** Begin PK *****\n");
  printf("p:\n");
  bn_print(t->p);
  printf("g:\n");
  g1_print(t->g);
  printf("h:\n");
  g1_print(t->h);
  printf("v:\n");
  g1_print(t->v);
  printf("w:\n");
  g1_print(t->w);
  printf("Omega:\n");
  g1_print(t->Omega);
  printf("\\hat{g}:\n");
  g2_print(t->gh);
  crs_print(t->crs);
  printf("***** End PK *****\n\n");
}

void sep_sign_init(sep_sign_t t)
{
  int i;
  for (i = 0; i < 3; ++i) {
    g1_null(t->sigma[i]);
    g1_new (t->sigma[i]);
    g1_set_infty(t->sigma[i]);
  }
  g1_null(t->pi);
  g1_new (t->pi);
  g1_set_infty(t->pi);
}

void sep_sign_free(sep_sign_t t)
{
  int i;
  for (i = 0; i < 3; ++i)
    g1_free(t->sigma[i]);
  g1_free(t->pi);
  free(t);
}

void sep_sign_print(const sep_sign_t t)
{
  int i;
  for (i = 0; i < 3; ++i) {
    printf("sigma_%d:\n", i+1);
    g1_print(t->sigma[i]);
    printf("\n");
  }
  printf("pi:\n");
  g1_print(t->pi);
  printf("\n");
}

int sep_keygen(sep_pk_t pk, sep_sk_t sk)
{
  int i;
  int result = STS_OK;
  bn_t chi[6];
  g1_t tmp1;

  for(i = 0; i < 6; ++i)
    bn_null(chi[i]);
  g1_null(tmp1);

  TRY {
    g1_new(tmp1);
    /* g, gh */
    g1_rand(pk->g);
    g2_rand(pk->gh);
    /* Order of 𝔾 */
    g1_get_ord(pk->p);
    /* omega */
    bn_rand_mod(sk, pk->p);
    /* g2 and gz */
    g2_rand(pk->crs->gz);
    for (i = 0; i < 6; ++i) {
      bn_new(chi[i]);
      bn_rand_mod(chi[i], pk->p);
      g2_mul(pk->crs->g2[i], pk->crs->gz, chi[i]);
    }

    /* vec(v) */
    g1_rand(pk->v);
    g1_rand(pk->w);
    /* h */
    g1_rand(pk->h);
    /* Omega */
    g1_mul(pk->Omega, pk->h, sk);
    /* z1 = g^{-χ₁} h^{-χ₆} */
    g1_mul(pk->crs->z[0], pk->g, chi[0]);
    g1_neg(pk->crs->z[0], pk->crs->z[0]);
    g1_mul(tmp1, pk->h, chi[5]);
    g1_sub(pk->crs->z[0], pk->crs->z[0], tmp1);
    /* z2 = v^{-χ₁} g^{-χ₂} h^{-χ₄} */
    g1_mul(tmp1, pk->v, chi[0]);
    g1_neg(tmp1, tmp1);
    g1_mul(pk->crs->z[1], pk->g, chi[1]);
    g1_sub(pk->crs->z[1], tmp1, pk->crs->z[1]);
    g1_mul(tmp1, pk->h, chi[3]);
    g1_sub(pk->crs->z[1], pk->crs->z[1], tmp1);
    /* z3 = w^{-χ₁} g^{-χ₃} h^{-χ₅} */
    g1_mul(tmp1, pk->w, chi[0]);
    g1_neg(tmp1, tmp1);
    g1_mul(pk->crs->z[2], pk->g, chi[2]);
    g1_sub(pk->crs->z[2], tmp1, pk->crs->z[2]);
    g1_mul(tmp1, pk->h, chi[4]);
    g1_sub(pk->crs->z[2], pk->crs->z[2], tmp1);
  }
  CATCH_ANY {
    result = STS_ERR;
  }
  FINALLY {
    g1_free(tmp1);
    for(i=0; i<6;++i)
      bn_free(chi[i]);
  }
  return result;
}

int sep_sign(sep_sign_t sig, const sep_sk_t sk, const sep_pk_t pk, const bn_t m)
{
  int result = STS_OK;
  g1_t tmp1;
  bn_t s;
  bn_null(s);
  g1_null(tmp1);
  TRY {
    bn_new(s);
    g1_new (tmp1);
    bn_rand_mod(s, pk->p);
    /* σ₁ */
    g1_mul(sig->sigma[0], pk->v, m);
    g1_add(sig->sigma[0], sig->sigma[0], pk->w);
    g1_mul(sig->sigma[0], sig->sigma[0], s);
    g1_mul(tmp1, pk->g, sk);
    g1_add(sig->sigma[0], tmp1, sig->sigma[0]);
    /* σ₂ */
    g1_mul(sig->sigma[1], pk->g, s);
    /* σ₃ */
    g1_mul(sig->sigma[2], pk->h, s);
    /* π */
    g1_mul(tmp1, pk->crs->z[0], sk);
    g1_mul(sig->pi, pk->crs->z[1], m);
    g1_add(sig->pi, sig->pi, pk->crs->z[2]);
    g1_mul(sig->pi, sig->pi, s);
    g1_add(sig->pi, tmp1, sig->pi);
  } CATCH_ANY {
    result = STS_ERR;
  } FINALLY {
    g1_free(tmp1);
    bn_free(s);
  }
  return result;
}

int sep_sign_blind(sep_sign_t sig, const sep_sk_t sk, const sep_pk_t pk, const g1_t M, const g1_t Z)
{
  int result = STS_OK;
  bn_t s;
  bn_null(s);
  g1_t tmp1;
  g1_null(tmp1);
  TRY {
    g1_new (tmp1);
    bn_new (s);
    bn_rand_mod(s, pk->p);
    /* σ₁ */
    g1_add(sig->sigma[0], M, pk->w);
    g1_mul(sig->sigma[0], sig->sigma[0], s);
    g1_mul(tmp1, pk->g, sk);
    g1_add(sig->sigma[0], tmp1, sig->sigma[0]);
    /* σ₂ */
    g1_mul(sig->sigma[1], pk->g, s);
    /* σ₃ */
    g1_mul(sig->sigma[2], pk->h, s);
    /* π */
    g1_mul(tmp1, pk->crs->z[0], sk);
    g1_add(sig->pi, Z, pk->crs->z[2]);
    g1_mul(sig->pi, sig->pi, s);
    g1_add(sig->pi, tmp1, sig->pi);
  } CATCH_ANY {
    result = STS_ERR;
  } FINALLY {
    g1_free(tmp1);
    bn_free(s);
  }
  return result;
}
int sep_verif(const sep_sign_t sig, const sep_pk_t pk, const bn_t m)
{
  int result = 0;
  gt_t e1;
  gt_t tmpt;
  g2_t tmp2;
  gt_null(e1); gt_null(tmpt);
  g2_null(tmp2);
  TRY {
    gt_new(e1); gt_new(tmpt);
    g2_new(tmp2);
    /* verif */
    /* e(Ω,g6) */
    pc_map(e1, pk->Omega, pk->crs->g2[5]);
    /* e(π,gz) */
    pc_map(tmpt, sig->pi, pk->crs->gz);
    gt_mul(e1, e1, tmpt);
    /* e(σ₁,g_1) */
    pc_map(tmpt, sig->sigma[0], pk->crs->g2[0]);
    gt_mul(e1, e1, tmpt);
    /* e(σ₂,g_2^m * g_3) */
    g2_mul(tmp2, pk->crs->g2[1], m);
    g2_add(tmp2, tmp2, pk->crs->g2[2]);
    pc_map(tmpt, sig->sigma[1], tmp2);
    gt_mul(e1, e1, tmpt);
    /* e(σ₃,g_4^m * g_5) */
    g2_mul(tmp2, pk->crs->g2[3], m);
    g2_add(tmp2, tmp2, pk->crs->g2[4]);
    pc_map(tmpt, sig->sigma[2], tmp2);
    gt_mul(e1, e1, tmpt);
    result = gt_is_unity(e1);
  } CATCH_ANY {
  } FINALLY {
    gt_free(tmpt); gt_free(e1);
    g2_free(tmp2);
  }
  return result;
}

/***************************/
/* Dynamic Group Signature */
/***************************/

void gs_pp_init(gs_pp_t t)
{
  t->pk_s = malloc(sizeof *(t->pk_s));
  sep_pk_init(t->pk_s);

  g1_null(t->Xz);
  g1_new (t->Xz);
  g1_null(t->Xs);
  g1_new (t->Xs);
  g1_null(t->Xid);
  g1_new (t->Xid);
}

void gs_pp_free(gs_pp_t t)
{
  sep_pk_free(t->pk_s);

  g1_free(t->Xz);
  g1_free(t->Xs);
  g1_free(t->Xid);
  free(t);
}

void gs_soa_init(gs_soa_t t)
{
  bn_null(t->xz)
  bn_new (t->xz)
  bn_null(t->yz)
  bn_new (t->yz)

  bn_null(t->xs)
  bn_new (t->xs)
  bn_null(t->ys)
  bn_new (t->ys)

  bn_null(t->xid)
  bn_new (t->xid)
  bn_null(t->yid)
  bn_new (t->yid)
}

void gs_soa_free(gs_soa_t t)
{
  bn_free(t->xz)
  bn_free(t->yz)
  bn_free(t->xs)
  bn_free(t->ys)
  bn_free(t->xid)
  bn_free(t->yid)
  free(t);
}

int gs_keygen(gs_pp_t pp, gs_sgm_t sgm, gs_soa_t soa)
{
  int result;
  g1_t tmp1;
  g1_null(tmp1);
  TRY {
    g1_new(tmp1);
    /* pp: pk_s + SGM */
    sep_keygen(pp->pk_s, sgm);
    /* soa: xz, yz, xs, ys, xid, yid */
    bn_rand_mod(soa->xz, pp->pk_s->p);
    bn_rand_mod(soa->yz, pp->pk_s->p);
    bn_rand_mod(soa->xs, pp->pk_s->p);
    bn_rand_mod(soa->ys, pp->pk_s->p);
    bn_rand_mod(soa->xid, pp->pk_s->p);
    bn_rand_mod(soa->yid, pp->pk_s->p);
    /* pp: Xz, Xs, Xid */
    g1_mul(pp->Xz, pp->pk_s->g, soa->xz);
    g1_mul(tmp1  , pp->pk_s->h, soa->yz);
    g1_add(pp->Xz, pp->Xz     , tmp1);
    g1_mul(pp->Xs, pp->pk_s->g, soa->xs);
    g1_mul(tmp1  , pp->pk_s->h, soa->ys);
    g1_add(pp->Xs, pp->Xs     , tmp1);
    g1_mul(pp->Xid, pp->pk_s->g, soa->xid);
    g1_mul(tmp1  , pp->pk_s->h, soa->yid);
    g1_add(pp->Xid, pp->Xid     , tmp1);
  }
  CATCH_ANY {
    result = STS_ERR;
  }
  FINALLY {
    g1_free(tmp1);
  }
  return result;
}


void msg_init(msg_t t, const size_t n)
{
  size_t i;
  t->len = n;
  t->msg = malloc(n * sizeof(t->msg));
  for (i = 0; i < n; ++i)
    t->msg[i] = 0;
}

int  msg_init_set(msg_t t, const char* s)
{
  int len, i;
  len = 0;
  for (i = 0; s[i] != '\0'; ++i) ;
  len = i;
  msg_init(t, len);
  if ( t->msg == NULL)
    return 0;
  for (i = 0; i < len; ++i)
    t->msg[i] = s[i];
  return 1;
}

void msg_free(msg_t t)
{
  free(t->msg);
  free(t);
}

void gs_cert_init(gs_cert_t t)
{
  bn_null(t->i);
  bn_new (t->i);
  g1_null(t->Vid);
  g1_new (t->Vid);
  t->sig = malloc(sizeof *(t->sig));
  sep_sign_init(t->sig);
}

void gs_cert_free(gs_cert_t t)
{
  bn_free(t->i);
  g1_free(t->Vid);
  sep_sign_free(t->sig);
  free(t);
}

void gs_sig_init(gs_sig_t t)
{
  g1_null(t->C[0])   ; g1_new(t->C[0])   ;
  g1_null(t->C[1])   ; g1_new(t->C[1])   ;
  g1_null(t->Cz)     ; g1_new(t->Cz)     ;
  g1_null(t->Cs)     ; g1_new(t->Cs)     ;
  g1_null(t->Cid)    ; g1_new(t->Cid)    ;
  g1_null(t->sig1)   ; g1_new(t->sig1)   ;
  g2_null(t->sig2)   ; g2_new(t->sig2)   ;
  bn_null(t->c)      ; bn_new(t->c)      ;
  bn_null(t->sid)    ; bn_new(t->sid)    ;
  bn_null(t->stheta) ; bn_new(t->stheta) ;
}

void gs_sig_free(gs_sig_t t)
{
  g1_free(t->C[0])   ;
  g1_free(t->C[1])   ;
  g1_free(t->Cz)     ;
  g1_free(t->Cs)     ;
  g1_free(t->Cid)    ;
  g1_free(t->sig1)   ;
  g2_free(t->sig2)   ;
  bn_free(t->c)      ;
  bn_free(t->sid)    ;
  bn_free(t->stheta) ;
  free(t);
}

void cdm_trans_init(cdm_trans_t t)
{
  g1_null(t->h)  ; g1_null(t->hh) ;
  bn_null(t->c)  ; g1_null(t->B)  ;
  bn_null(t->ii) ; bn_null(t->jj) ;
  bn_null(t->k)  ;
  bn_null(t->r)  ; bn_null(t->z)  ;

  g1_new(t->h)   ; g1_new(t->hh)  ;
  bn_new(t->c)   ; g1_new(t->B)   ;
  bn_new(t->ii)  ; bn_new(t->jj)  ;
  bn_new(t->k)   ;
  bn_new(t->r)   ; bn_new(t->z)   ;
}

void cdm_trans_free(cdm_trans_t t)
{
  g1_free(t->h)  ; g1_free(t->hh) ;
  bn_free(t->c)  ; g1_free(t->B)  ;
  g1_free(t->ii) ; g1_free(t->jj) ;
  bn_free(t->k)  ;
  bn_free(t->r)  ; g1_free(t->z)  ;
  free(t)        ;
}


int cdm_run(cdm_trans_t pi, bn_t q, g1_t X, g1_t g, bn_t a)
{
  bn_t i, j, ii, jj;
  bn_null(i)  ; bn_null(j)  ;
  bn_null(ii) ; bn_null(jj) ;
  bn_new (i)  ; bn_new (j)  ;
  bn_new (ii) ; bn_new (jj) ;
  bn_t p;
  bn_null(p);
  bn_new (p);
  g1_t tmp;
  g1_null(tmp);
  g1_new (tmp);
  g1_t lhs, rhs;
  g1_null(lhs); g1_null(rhs); 
  g1_new (lhs); g1_new (rhs); 
  bn_t exponents;
  bn_null(exponents);
  bn_new (exponents);

  /* Verifier */
  bn_rand_mod(i , q); bn_rand_mod (j , q);
  bn_rand_mod(ii, q); bn_rand_mod (jj, q);
  /* h */
  g1_mul(pi->h, g, i); 
  g1_mul(tmp, X, j);
  g1_add(pi->h, pi->h, tmp);
  /* h' */
  g1_mul(pi->hh, g, ii);
  g1_mul(tmp, X, jj);
  g1_add(pi->hh, pi->hh, tmp);

  /* Prover */
  bn_rand_mod(pi->c, q);
  bn_rand_mod(p, q); bn_rand_mod(pi->r, q);

  bn_mul(exponents, a, pi->c);
  bn_mul(exponents, exponents, pi->r);
  bn_add(exponents, p, exponents);
  bn_mod(exponents, exponents, q);
  g1_mul(pi->B, g, exponents);
  g1_mul(tmp, pi->h, pi->r);
  g1_add(pi->B, pi->B, tmp);

  /* Verifier */
  bn_mul(pi->ii, i, pi->c);
  bn_add(pi->ii, pi->ii, ii);
  bn_mod(pi->ii, pi->ii, q); /* i'' = i*c+i' */
  bn_mul(pi->jj, j, pi->c);
  bn_add(pi->jj, pi->jj, jj);
  bn_mod(pi->jj, pi->jj, q);
  bn_rand_mod(pi->k, q);


  /* Prover */
  bn_mul(exponents, a, pi->jj);
  bn_add(exponents, pi->ii, exponents);
  bn_mod(exponents, exponents, q);
  g1_mul(lhs, g, exponents);

  g1_mul(rhs, pi->h, pi->c);
  g1_add(rhs, rhs, pi->hh);
  if (g1_cmp(lhs, rhs) == CMP_NE) {
    fprintf(stderr, "Error: Prover. g^{i'+x j''} ≠ h^c h'\n");
    return 0;
  }
  bn_mul(pi->z, pi->k, a);
  bn_add(pi->z, p, pi->z);

  /* Verifier */
  bn_mul(exponents, i, pi->r);
  bn_add(exponents, pi->z, exponents);
  bn_mod(exponents, exponents, q);
  g1_mul(lhs, g, exponents);

  bn_add(exponents, pi->c, j);
  bn_mul(exponents, exponents, pi->r);
  bn_sub(exponents, pi->k, exponents);
  bn_mod(exponents, exponents, q);
  g1_mul(rhs, X, exponents);
  g1_add(rhs, rhs, pi->B);
  if (g1_cmp(lhs, rhs) == CMP_NE) {
    fprintf(stderr, "Error: Verifier. g^{z+ir} ≠ X^{k-(c+j)r}\n");
    return 0;
  }
  return 1;
}

void gs_trans_init(gs_trans_t t)
{
  t->trans = malloc(sizeof *(t->trans));
  assert(t->trans != NULL);
  cdm_trans_init(t->trans);
  t->cert = malloc(sizeof *(t->cert));
  assert(t->cert != NULL);
  gs_cert_init(t->cert);

  g1_null(t->Zid);
  g2_null(t->G2id); g2_null(t->G4id);

  g1_new(t->Zid);
  g2_new(t->G2id); g2_new(t->G4id);
}

void gs_trans_free(gs_trans_t t)
{
  cdm_trans_free(t->trans);
  gs_cert_free(t->cert);
  g1_free(t->Zid);
  g2_free(t->G2id); g2_free(t->G4id);
  free(t);
}


void gs_id_exc_init(gs_id_exc_t t)
{
  g1_null(t->Vid);
  g1_null(t->Zid);
  g2_null(t->G2id);
  g2_null(t->G4id);

  g1_new (t->Vid);
  g1_new (t->Zid);
  g2_new (t->G2id);
  g2_new (t->G4id);

  g1_set_infty(t->Vid);
  g1_set_infty(t->Zid);
  g2_set_infty(t->G2id);
  g2_set_infty(t->G4id);
}

void gs_id_exc_set(gs_id_exc_t t, gs_pp_t pp, bn_t ID)
{
  g1_mul(t->Vid, pp->pk_s->v, ID);
  g1_mul(t->Zid, pp->pk_s->crs->z[1], ID);
  g2_mul(t->G2id, pp->pk_s->crs->g2[1], ID);
  g2_mul(t->G4id, pp->pk_s->crs->g2[3], ID);
}

void gs_id_exc_free(gs_id_exc_t t)
{
  g1_free(t->Vid);
  g1_free(t->Zid);
  g2_free(t->G2id);
  g2_free(t->G4id);

  free(t);
}

/*******************/
/* Group Signature */
/*******************/

int gs_sign(gs_sig_t sig, const gs_pp_t pp, const gs_sec_t sec, const gs_cert_t cert, const msg_t m)
{
  int result = STS_OK;
  g1_t    tmp1 ; gt_t    tmpt ; gt_t    tmpt2 ;
  g1_null(tmp1); gt_null(tmpt); gt_null(tmpt2);
  g1_t    R1 ,         R2 ,         R3 ;
  g1_null(R1); g1_null(R2); g1_null(R3);
  gt_t    R4;
  gt_null(R4);
  bn_t    r ,         rtheta ,         rid ;
  bn_null(r); bn_null(rtheta); bn_null(rid);
  bn_t    theta ;
  bn_null(theta);
  gs_cert_t sigma_rand;
  TRY {
    sigma_rand = malloc(sizeof *sigma_rand);
    assert      (sigma_rand != 0);
    gs_cert_init(sigma_rand);
    g1_new(tmp1);
    gt_new(tmpt); gt_new(tmpt2);
    bn_new(r); bn_new(rtheta); bn_new(rid);
    bn_rand_mod(r, pp->pk_s->p);
    /* σ₂ */
    g1_mul(sigma_rand->sig->sigma[1], pp->pk_s->g, r);
    g1_add(sigma_rand->sig->sigma[1], cert->sig->sigma[1], sigma_rand->sig->sigma[1]);
    g1_copy(sig->sig1, sigma_rand->sig->sigma[1]);
    /* σ₃ */
    g1_mul(sigma_rand->sig->sigma[2], pp->pk_s->h, r);
    g1_add(sigma_rand->sig->sigma[2], cert->sig->sigma[2], sigma_rand->sig->sigma[2]);
    g1_copy(sig->sig2, sigma_rand->sig->sigma[2]);
    /* σ₁ */
    g1_mul(sigma_rand->sig->sigma[0], pp->pk_s->v, sec );
    g1_add(sigma_rand->sig->sigma[0], sigma_rand->sig->sigma[0], pp->pk_s->w);
    g1_mul(sigma_rand->sig->sigma[0], sigma_rand->sig->sigma[0], r);
    g1_add(sigma_rand->sig->sigma[0], cert->sig->sigma[0], sigma_rand->sig->sigma[0]);
    /* π */
    g1_mul(sigma_rand->sig->pi, pp->pk_s->crs->z[1], sec );
    g1_add(sigma_rand->sig->pi, sigma_rand->sig->pi, pp->pk_s->crs->z[2]);
    g1_mul(sigma_rand->sig->pi, sigma_rand->sig->pi, r);
    g1_add(sigma_rand->sig->pi, cert->sig->pi, sigma_rand->sig->pi);
    /* Cramer-Shoup encryption */
    bn_new(theta);
    bn_rand_mod(theta, pp->pk_s->p);
    /** C1 **/
    g1_mul(sig->C[0], pp->pk_s->g, theta);
    /** C2 **/
    g1_mul(sig->C[1], pp->pk_s->h, theta);
    /** Cz **/
    g1_mul(sig->Cz, pp->Xz, theta);
    g1_add(sig->Cz, sigma_rand->sig->pi, sig->Cz);
    /** Cσ **/
    g1_mul(sig->Cs, pp->Xs, theta);
    g1_add(sig->Cs, sigma_rand->sig->sigma[0], sig->Cs);
    /** Cid **/
    g1_mul(sig->Cid, pp->Xid, theta);
    g1_mul(tmp1, pp->pk_s->v, sec);
    g1_add(sig->Cid, tmp1, sig->Cid);
    /* ZK Proof */
    bn_rand_mod(rid, pp->pk_s->p); bn_rand_mod(rtheta, pp->pk_s->p);
    g1_new(R1); g1_new(R2); g1_new(R3);
    gt_new(R4);
    /** R1 **/
    g1_mul(R1, pp->pk_s->g, rtheta);
    /** R2 **/
    g1_mul(R2, pp->pk_s->h, rtheta);
    /** R3 **/
    g1_mul(R3, pp->Xid, rtheta);
    g1_mul(tmp1, pp->pk_s->v, rid);
    g1_add(R3, tmp1, R3);
    /** R4 **/
    /*** (e(Xz, gz) · e(Xσ, g1))^rθ ***/
    pc_map(R4, pp->Xz, pp->pk_s->crs->gz);
    pc_map(tmpt, pp->Xs, pp->pk_s->crs->g2[0]);
    gt_mul(R4, R4, tmpt);
    gt_exp(R4, R4, rtheta);
    /*** (e(σ2, g2) · e(σ3, g4))^-rid ***/
    pc_map(tmpt , sigma_rand->sig->sigma[1], pp->pk_s->crs->g2[1]);
    pc_map(tmpt2, sigma_rand->sig->sigma[2], pp->pk_s->crs->g2[3]);
    gt_mul(tmpt, tmpt, tmpt2);
    gt_exp(tmpt, tmpt, rid);
    gt_inv(tmpt, tmpt);
    /*** R4 **/
    gt_mul(R4, R4, tmpt);
    /* Normalize */
    g1_norm(R1, R1);
    g1_norm(R2, R3);
    g1_norm(R3, R3);
    /* c, sθ, sid */
    uint8_t H[32];
    uint8_t* msg;
    unsigned int i;
    unsigned int hash_len = m->len + g1_size_bin(R1, 1) * 10 + gt_size_bin(R4, 1);
    msg = malloc(hash_len * sizeof *msg);
    assert(msg != NULL);
    for(i = 0; i < m->len; ++i)
      msg[i] = m->msg[i];
    g1_write_bin(msg + m->len + 0  * g1_size_bin(R1 , 1) , g1_size_bin(sig->C[0] , 1) , sig->C[0] , 1);
    g1_write_bin(msg + m->len + 1  * g1_size_bin(R1 , 1) , g1_size_bin(sig->C[1] , 1) , sig->C[1] , 1);
    g1_write_bin(msg + m->len + 2  * g1_size_bin(R1 , 1) , g1_size_bin(sig->Cz   , 1) , sig->Cz   , 1);
    g1_write_bin(msg + m->len + 3  * g1_size_bin(R1 , 1) , g1_size_bin(sig->Cs   , 1) , sig->Cs   , 1);
    g1_write_bin(msg + m->len + 4  * g1_size_bin(R1 , 1) , g1_size_bin(sig->Cid  , 1) , sig->Cid  , 1);
    g1_write_bin(msg + m->len + 5  * g1_size_bin(R1 , 1) , g1_size_bin(sig->sig1 , 1) , sig->sig1 , 1);
    g1_write_bin(msg + m->len + 6  * g1_size_bin(R1 , 1) , g1_size_bin(sig->sig2 , 1) , sig->sig2 , 1);
    g1_write_bin(msg + m->len + 7  * g1_size_bin(R1 , 1) , g1_size_bin(R1        , 1) , R1        , 1);
    g1_write_bin(msg + m->len + 8  * g1_size_bin(R1 , 1) , g1_size_bin(R2        , 1) , R2        , 1);
    g1_write_bin(msg + m->len + 9  * g1_size_bin(R1 , 1) , g1_size_bin(R3        , 1) , R3        , 1);
    gt_write_bin(msg + m->len + 10 * g1_size_bin(R1 , 1) , gt_size_bin(R4        , 1) , R4        , 1);
    md_map_sh256(H, msg, hash_len);
    free(msg);
    /** c **/
    bn_read_bin(sig->c, H, 32);
    /** sθ **/
    bn_mul(sig->stheta, sig->c, theta);
    bn_add(sig->stheta, rtheta, sig->stheta);
    bn_mod(sig->stheta, sig->stheta, pp->pk_s->p);
    /** sID **/
    bn_mul(sig->sid, sig->c, sec);
    bn_add(sig->sid, rid, sig->sid);
    bn_mod(sig->sid, sig->sid, pp->pk_s->p);
  }
  CATCH_ANY {
    result = STS_ERR;
  }
  FINALLY {
    g1_free(tmp1); gt_free(tmpt); gt_free(tmpt2);
    g1_free(R1); g1_free(R2); g1_free(R3);
    gt_free(R4);
    bn_free(r); bn_free(rtheta); bn_free(rid);
    bn_free(theta);
    gs_cert_free(sigma_rand);
  }
  return result;
}

int gs_verif(const gs_pp_t pp, const msg_t m, const gs_sig_t sig)
{
  int result = STS_OK;
  g1_t    tmp1 ;
  g1_null(tmp1);
  g1_t    R1 ,         R2 ,         R3 ;
  g1_null(R1); g1_null(R2); g1_null(R3);
  gt_t    R4;
  gt_null(R4);
  gt_t    tmpt ,         tmpt2 ;
  gt_null(tmpt); gt_null(tmpt2);
  bn_t conv_H;
  bn_null(conv_H);

  TRY {
    g1_new(tmp1);
    g1_new(R1); g1_new(R2); g1_new(R3);
    gt_new(R4);
    /* R1 */
    g1_mul(R1, sig->C[0], sig->c);
    g1_mul(tmp1, pp->pk_s->g, sig->stheta);
    g1_sub(R1, tmp1, R1);
    /* R2 */
    g1_mul(R2, sig->C[1], sig->c);
    g1_neg(R2, R2);
    g1_mul(tmp1, pp->pk_s->g, sig->stheta);
    g1_add(R2, tmp1, R2);
    /* R3 */
    g1_mul(R3, sig->Cid, sig->c);
    g1_neg(R3, R3);
    g1_mul(tmp1, pp->Xid, sig->stheta);
    g1_add(R3, tmp1, R3);
    g1_mul(tmp1, pp->pk_s->v, sig->sid);
    g1_add(R3, tmp1, R3);
    /* R4 */
    /* e(Cz, ĝz) e(Cs, ĝ1) e(~σ2, ĝ3) e(~σ3, ĝ5) e(Ω, ĝ6) ^-c */
    pc_map(R4, sig->Cz, pp->pk_s->crs->gz);
    pc_map(tmpt, sig->Cs, pp->pk_s->crs->g2[0]);
    gt_mul(R4, R4, tmpt);
    pc_map(tmpt, sig->sig1, pp->pk_s->crs->g2[2]);
    gt_mul(R4, R4, tmpt);
    pc_map(tmpt, sig->sig2, pp->pk_s->crs->g2[4]);
    gt_mul(R4, R4, tmpt);
    pc_map(tmpt, pp->pk_s->Omega, pp->pk_s->crs->g2[5]);
    gt_mul(R4, R4, tmpt);
    gt_exp(R4, R4, sig->c);
    gt_inv(R4, R4);
    /* e(~σ2, ĝ2) e(~s3, ĝ4) ^ -sid */
    pc_map(tmpt,  sig->sig1, pp->pk_s->crs->g2[1]);
    pc_map(tmpt2, sig->sig2, pp->pk_s->crs->g2[3]);
    gt_mul(tmpt, tmpt, tmpt2);
    gt_exp(tmpt, tmpt, sig->sid);
    gt_inv(tmpt, tmpt);
    gt_mul(R4, tmpt, R4);
    /* (e(Xz, ĝz) e(Xσ, ĝ1))^s_θ */
    pc_map(tmpt,  pp->Xz, pp->pk_s->crs->gz);
    pc_map(tmpt2, pp->Xs, pp->pk_s->crs->g2[0]);
    gt_mul(tmpt, tmpt, tmpt2);
    gt_exp(tmpt, tmpt, sig->stheta);
    gt_mul(R4, tmpt, R4);
    /* Normalize */
    g1_norm(R1, R1);
    g1_norm(R2, R3);
    g1_norm(R3, R3);
    /* H */
    uint8_t H[32];
    uint8_t* msg;
    unsigned int i;
    unsigned int hash_len = m->len + g1_size_bin(R1, 1) * 10 + gt_size_bin(R4, 1);
    msg = malloc(hash_len * sizeof(uint8_t));
    assert(msg != NULL);
    for(i = 0; i < m->len; ++i)
      msg[i] = m->msg[i];
    g1_write_bin(msg + m->len + 0  * g1_size_bin(R1 , 1) , g1_size_bin(sig->C[0] , 1) , sig->C[0] , 1);
    g1_write_bin(msg + m->len + 1  * g1_size_bin(R1 , 1) , g1_size_bin(sig->C[1] , 1) , sig->C[1] , 1);
    g1_write_bin(msg + m->len + 2  * g1_size_bin(R1 , 1) , g1_size_bin(sig->Cz   , 1) , sig->Cz   , 1);
    g1_write_bin(msg + m->len + 3  * g1_size_bin(R1 , 1) , g1_size_bin(sig->Cs   , 1) , sig->Cs   , 1);
    g1_write_bin(msg + m->len + 4  * g1_size_bin(R1 , 1) , g1_size_bin(sig->Cid  , 1) , sig->Cid  , 1);
    g1_write_bin(msg + m->len + 5  * g1_size_bin(R1 , 1) , g1_size_bin(sig->sig1 , 1) , sig->sig1 , 1);
    g1_write_bin(msg + m->len + 6  * g1_size_bin(R1 , 1) , g1_size_bin(sig->sig2 , 1) , sig->sig2 , 1);
    g1_write_bin(msg + m->len + 7  * g1_size_bin(R1 , 1) , g1_size_bin(R1        , 1) , R1        , 1);
    g1_write_bin(msg + m->len + 8  * g1_size_bin(R1 , 1) , g1_size_bin(R2        , 1) , R2        , 1);
    g1_write_bin(msg + m->len + 9  * g1_size_bin(R1 , 1) , g1_size_bin(R3        , 1) , R3        , 1);
    gt_write_bin(msg + m->len + 10 * g1_size_bin(R1 , 1) , gt_size_bin(R4        , 1) , R4        , 1);
    md_map_sh256(H, msg, hash_len);
    free(msg);
    bn_new(conv_H);
    bn_read_bin(conv_H, H, 32);

    /* Compare */
    result = (bn_cmp(sig->c, conv_H) == CMP_EQ);
  }
  CATCH_ANY {
  }
  FINALLY {
  g1_free(tmp1);
  g1_free(R1); g1_free(R2); g1_free(R3);
  gt_free(R4);
  gt_free(tmpt); gt_free(tmpt2);
  bn_free(conv_H);
  }
  return result;
}

int gs_join(gs_cert_t cert, gs_sec_t sec, gs_trans_t trans, const gs_pp_t pp, const gs_sgm_t sgm)
{
  int result = STS_OK;
  bn_t ID;
  bn_null(ID);
  bn_t s;
  bn_null(s);
  gs_id_exc_t initialize = malloc(sizeof *initialize);
  /* For equality check */
  gt_t lhs, rhs;
  gt_null(lhs); gt_null(rhs);
  /* Cramer Damgård MacKenzie */
  cdm_trans_t pik = trans->trans;

  TRY {
    /* User: Generate ID and first message */
    bn_new(ID);
    bn_rand_mod(ID, pp->pk_s->p);
    bn_copy(sec, ID);
    gs_id_exc_init(initialize);
    gs_id_exc_set(initialize, pp, ID);

    /* GM part */
    gt_new(lhs); gt_new(rhs);
    /* k = 2 */
    pc_map(lhs, initialize->Vid, pp->pk_s->crs->g2[1]);
    pc_map(rhs, pp->pk_s->v, initialize->G2id);
    int ok = 1;
    if (gt_cmp(lhs, rhs) == CMP_NE) {
      ok = 0;
      fprintf(stderr, "Error on verification e(Vid, ĝ_2) = e(g, Ĝ_2,id)\n");
    }
    pc_map(lhs, initialize->Zid, pp->pk_s->crs->g2[1]);
    pc_map(rhs, pp->pk_s->crs->z[1], initialize->G2id);
    if (gt_cmp(lhs, rhs) == CMP_NE) {
      ok = 0;
      fprintf(stderr, "Error on verification e(Zid, ĝ_2) = e(g, Ĝ_2,id)\n");
    }
    /* k = 4 */
    pc_map(lhs, initialize->Vid, pp->pk_s->crs->g2[3]);
    pc_map(rhs, pp->pk_s->v, initialize->G4id);
    if (gt_cmp(lhs, rhs) == CMP_NE) {
      ok = 0;
      fprintf(stderr, "Error on verification e(Vid, ĝ_4) = e(g, Ĝ_2,id)\n");
    }
    pc_map(lhs, initialize->Zid, pp->pk_s->crs->g2[3]);
    pc_map(rhs, pp->pk_s->crs->z[1], initialize->G4id);
    if (gt_cmp(lhs, rhs) == CMP_NE) {
      ok = 0;
      fprintf(stderr, "Error on verification e(Zid, ĝ_4) = e(g, Ĝ_2,id)\n");
    }
    assert(ok);
    bn_rand_mod(cert->i, pp->pk_s->p);

    /* Cramer Damgard MacKenzie */
    if (!(cdm_run(pik, pp->pk_s->p, initialize->Vid, pp->pk_s->v, ID))) {
      fprintf(stderr, "Error in ZK proof.\n");
      result = STS_ERR;
    }

    /* Sign */
    bn_new(s);
    sep_sign_blind(cert->sig, sgm, pp->pk_s, initialize->Vid, initialize->Zid);
    g1_copy(cert->Vid, initialize->Vid);
  } CATCH_ANY {
    result = STS_ERR;
  } FINALLY {
    bn_free(ID);
    bn_free(s);
    gs_id_exc_free(initialize);
    gt_free(lhs); gt_free(rhs);
  }
  return result;
}

int gs_open(g1_t ID, const gs_soa_t soa, const gs_sig_t sig)
{
  int result = 0;
  g1_t sigma1, pi, Vid;
  g1_t tmp1;
  g1_null(sigma1); g1_null(pi); g1_null(Vid);
  g1_null(tmp1);
  TRY {
    g1_new(tmp1);
    /* σ₁ */
    g1_new(sigma1);
    g1_mul(sigma1, sig->C[1], soa->ys);
    g1_mul(tmp1, sig->C[0], soa->xs);
    g1_add(sigma1, tmp1, sigma1);
    g1_neg(sigma1, sigma1);
    g1_add(sigma1, sig->Cs, sigma1);
    /* π */
    g1_new(pi);
    g1_mul(pi, sig->C[1], soa->yz);
    g1_mul(tmp1, sig->C[0], soa->xz);
    g1_add(pi, tmp1, pi);
    g1_neg(pi, pi);
    g1_add(pi, sig->Cz, pi);
    /* Vid */
    g1_new(Vid);
    g1_mul(Vid, sig->C[1], soa->yid);
    g1_mul(tmp1, sig->C[0], soa->xid);
    g1_add(Vid, tmp1, Vid);
    g1_neg(Vid, Vid);
    g1_add(Vid, sig->Cid, Vid);

    /* temporarily */
    g1_copy(ID, Vid);
  } CATCH_ANY {
    result = STS_ERR;
  } FINALLY {
    g1_free(sigma1); g1_null(pi); g1_null(Vid);
    g1_free(tmp1);
  }
  return result;
}
