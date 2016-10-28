/*
version 20081011
Matthew Dempsky
Public domain.
Derived from public domain code by D. J. Bernstein.
*/


extern int crypto_scalarmult(unsigned char *q, const unsigned char *n, const unsigned char *p);
const unsigned char base[32] = {9};

int crypto_scalarmult_base(unsigned char *q, const unsigned char *n)
{
  return crypto_scalarmult(q,n,base);
}
