#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ---------------------------------------------------------------
   RSA simples em C — geração de chaves, cifragem e decifragem
   Usa primos pequenos para fins didáticos. Para produção, use
   uma biblioteca criptográfica (OpenSSL, libgcrypt, etc.).
   --------------------------------------------------------------- */

typedef long long ll;

/* Máximo Divisor Comum */
ll mdc(ll a, ll b) {
    while (b) { ll t = b; b = a % b; a = t; }
    return a;
}

/* Exponenciação modular: base^exp mod m */
ll exp_mod(ll base, ll exp, ll m) {
    ll resultado = 1;
    base %= m;
    while (exp > 0) {
        if (exp & 1) resultado = resultado * base % m;
        base = base * base % m;
        exp >>= 1;
    }
    return resultado;
}

/* Inverso modular de a mod m via algoritmo estendido de Euclides */
ll inverso_mod(ll a, ll m) {
    ll m0 = m, x0 = 0, x1 = 1;
    if (m == 1) return 0;
    while (a > 1) {
        ll q = a / m;
        ll t = m;
        m = a % m; a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    if (x1 < 0) x1 += m0;
    return x1;
}

/* Verifica primalidade (simples, adequada para demos) */
int eh_primo(ll n) {
    if (n < 2) return 0;
    for (ll i = 2; i * i <= n; i++)
        if (n % i == 0) return 0;
    return 1;
}

/* -------- Estrutura de chave -------- */
typedef struct { ll chave, n; } RSAChave;

/* -------- Geração de chaves -------- */
void rsa_gerar_chaves(ll p, ll q, RSAChave *publica, RSAChave *privada) {
    if (!eh_primo(p) || !eh_primo(q)) {
        fprintf(stderr, "Erro: p e q devem ser primos.\n");
        exit(1);
    }

    ll n    = p * q;
    ll phi  = (p - 1) * (q - 1);

    /* Escolhe e: 1 < e < phi, mdc(e, phi) = 1 */
    ll e = 2;
    while (e < phi && mdc(e, phi) != 1) e++;

    ll d = inverso_mod(e, phi);

    publica->chave  = e;  publica->n  = n;
    privada->chave  = d;  privada->n  = n;

    printf("=== Geração de Chaves RSA ===\n");
    printf("  p = %lld, q = %lld\n", p, q);
    printf("  n = p*q = %lld\n", n);
    printf("  phi(n) = %lld\n", phi);
    printf("  e (chave pblica)  = %lld\n", e);
    printf("  d (chave privada)  = %lld\n\n", d);
}

/* -------- Cifrar / decifrar -------- */
ll rsa_cifrar(ll msg, RSAChave pub) {
    return exp_mod(msg, pub.chave, pub.n);
}

ll rsa_decifrar(ll cifrado, RSAChave priv) {
    return exp_mod(cifrado, priv.chave, priv.n);
}

/* -------- Cifrar string (caractere a caractere) -------- */
void rsa_cifrar_texto(const char *texto, RSAChave pub,
                      ll *saida, int *tamanho) {
    *tamanho = (int)strlen(texto);
    for (int i = 0; i < *tamanho; i++)
        saida[i] = rsa_cifrar((ll)(unsigned char)texto[i], pub);
}

void rsa_decifrar_texto(const ll *cifrado, int tamanho,
                        RSAChave priv, char *saida) {
    for (int i = 0; i < tamanho; i++)
        saida[i] = (char)rsa_decifrar(cifrado[i], priv);
    saida[tamanho] = '\0';
}

/* -------- Demo -------- */
int main(void) {
    /* Primos pequenos — apenas para demonstração */
    ll p = 61, q = 53;

    RSAChave pub, priv;
    rsa_gerar_chaves(p, q, &pub, &priv);

    /* --- Teste numérico --- */
    ll mensagem = 65;   /* 'A' */
    ll cifrado  = rsa_cifrar(mensagem, pub);
    ll decifrado = rsa_decifrar(cifrado, priv);

    printf("=== Teste Numerico ===\n");
    printf("  Mensagem original : %lld\n", mensagem);
    printf("  Cifrado           : %lld\n", cifrado);
    printf("  Decifrado         : %lld\n\n", decifrado);

    /* --- Teste de texto --- */
    const char *texto = "RSA";
    int tam;
    ll buf[256];
    char recuperado[256];

    rsa_cifrar_texto(texto, pub, buf, &tam);
    rsa_decifrar_texto(buf, tam, priv, recuperado);

    printf("=== Teste de Texto ===\n");
    printf("  Original  : %s\n", texto);
    printf("  Cifrado   : ");
    for (int i = 0; i < tam; i++) printf("%lld ", buf[i]);
    printf("\n  Decifrado : %s\n", recuperado);

    return 0;
}