#ifndef SIGMASIG_H
#define SIGMASIG_H

/*******/
/* CRS */
/*******/

struct crs_t {
  g1_t z[3];
  g2_t gz;
  g2_t g2[6];
};

typedef struct crs_t* crs_t;

void crs_init (crs_t t);
void crs_free (crs_t t);
void crs_print(const crs_t t);

/**************************************/
/* Signature with efficient protocols */
/**************************************/

typedef bn_t sep_sk_t;

struct sep_pk_t {
  g1_t g, h, v, w, Omega;
  g2_t gh;
  bn_t p;
  crs_t crs;
};

typedef struct sep_pk_t* sep_pk_t;

struct sep_sign_t {
  g1_t sigma[3];
  g1_t pi;
};

typedef struct sep_sign_t* sep_sign_t;

void sep_pk_init(sep_pk_t t);
void sep_pk_free(sep_pk_t t);
void sep_pk_print(const sep_pk_t t);
void sep_sign_init(sep_sign_t t);
void sep_sign_free(sep_sign_t t);
void sep_sign_print(const sep_sign_t t);

int sep_keygen(sep_pk_t pk, sep_sk_t sk);
int sep_sign(sep_sign_t sig, const sep_sk_t sk, const sep_pk_t pk, const bn_t m);
int sep_sign_blind(sep_sign_t sig, const sep_sk_t sk, const sep_pk_t pk, const g1_t M, const g1_t Z);
int sep_verif(const sep_sign_t sig, const sep_pk_t pk, const bn_t m);

/***************************/
/* Dynamic Group Signature */
/***************************/
/* Data structures */
/*******************/

struct gs_pp_t {
  sep_pk_t pk_s;
  g1_t Xz, Xs, Xid;
};

typedef struct gs_pp_t* gs_pp_t;

void gs_pp_init(gs_pp_t t);
void gs_pp_free(gs_pp_t t);

typedef sep_sk_t gs_sgm_t;

struct gs_soa_t {
  bn_t xz, yz;
  bn_t xs, ys;
  bn_t xid, yid;
};

typedef struct gs_soa_t* gs_soa_t;

void gs_soa_init(gs_soa_t t);
void gs_soa_free(gs_soa_t t);

struct gs_cert_t {
  bn_t i;
  g1_t Vid;
  sep_sign_t sig;
};

typedef struct gs_cert_t* gs_cert_t;
typedef bn_t gs_sec_t;

struct msg_t {
  uint8_t* msg;
  unsigned int len;
};

typedef struct msg_t* msg_t;
void msg_init(msg_t t, const size_t n);
int  msg_init_set(msg_t t, const char* s);
void msg_free(msg_t t);

void gs_cert_init(gs_cert_t t);
void gs_cert_free(gs_cert_t t);

struct gs_sig_t {
  g1_t C[2], Cz, Cs, Cid; // Cramer-Shoup encryption
  g1_t sig1, sig2;
  bn_t c, sid, stheta;
};

typedef struct gs_sig_t* gs_sig_t;
void gs_sig_init(gs_sig_t t);
void gs_sig_free(gs_sig_t t);

struct cdm_trans_t { /* Cramer-Damgard-McKenzie proof transcript */
  g1_t h, hh;
  bn_t c; g1_t B;
  bn_t ii , jj, k;
  bn_t r, z;
};

typedef struct cdm_trans_t* cdm_trans_t;

void cdm_trans_init(cdm_trans_t t);
void cdm_trans_free(cdm_trans_t t);
/**
 * Run Cramer-Damgard MacKenzie proof of knowledge
 *
 * @param[out] pi      - the transcript of the proof
 * @param[in]  p       - the size of the group
 * @param[in]  X, g, a - X = g^a
 * @return 1 if the proof is correct, 0 otherwise
 */
int cdm_run(cdm_trans_t pi, bn_t p, g1_t X, g1_t g, bn_t a); // prove h = g^a.

struct gs_trans_t {
  g1_t Zid;
  g2_t G2id, G4id;
  cdm_trans_t trans;
  gs_cert_t cert;
};

typedef struct gs_trans_t* gs_trans_t;

void gs_trans_init(gs_trans_t t);
void gs_trans_free(gs_trans_t t);

struct gs_id_exc_t {
  g1_t Vid, Zid;
  g2_t G2id, G4id;
};

typedef struct gs_id_exc_t* gs_id_exc_t;

void gs_id_exc_init(gs_id_exc_t t);
void gs_id_exc_set(gs_id_exc_t t, gs_pp_t pp, bn_t ID);
void gs_id_exc_free(gs_id_exc_t t);
/* Dynamic GS */
/**************/

int gs_keygen(gs_pp_t pp, gs_sgm_t sgm, gs_soa_t soa);
int gs_sign(gs_sig_t sig, const gs_pp_t pp, const gs_sec_t sec, const gs_cert_t cert, const msg_t m);
int gs_verif(const gs_pp_t pp, const msg_t m, const gs_sig_t sig);
int gs_join(gs_cert_t cert, gs_sec_t sec, gs_trans_t trans, const gs_pp_t pp, const gs_sgm_t sgm);

#endif
