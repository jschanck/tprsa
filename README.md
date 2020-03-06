
# tprsa.py : Tweetable PNG RSA

> This place is not a place of honor... <br>
> no highly esteemed deed is commemorated here... <br>
> nothing valued is here.

tprsa.py generates PNG-encoded half-megabyte multi-power RSA keys.

The keys are encoded in the RGBA channels of a 497 x 312 image.
Only 7 bits per channel are used. The top bit of the A channel must be 1.
The top bits of the RGB channels are yours to play with.
See the "mask" command below.

Expect key generation to take ~8 minutes.

tprsa.py also implements a simple key encapsulation mechanism, as specified in the PQRSA NIST submission.

# Usage
gen: Generate a key.

``` $ ./pqrsa.py gen private.pkl public.png ```

enc: Encrypt a random 32 byte key to public.png.
     Outputs the ciphertext in ciphertext.png,
     and the 32 byte key on stdout.

``` $ ./pqrsa.py enc public.png ciphertext.png ```

dec: Decrypt ciphertext.png.

``` $ ./pqrsa.py dec private.pkl ciphertext.png ```

fingerprint: Print the base64 encoding of the sha3 digest
     of the key or ciphertext in file.png.

``` $ ./pqrsa.py fingerprint file.png ```

mask: Copy the top bits of RGB channels from mask.png into img.png

``` $ ./pqrsa.py mask image.png mask.png ```

