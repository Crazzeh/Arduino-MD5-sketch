#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

void setup() {
  Serial.begin(9600);
}

void loop() {
  //Have we received a message?
  if (Serial.available()) {
    //Read the message
    String in = Serial.readString();
    Serial.print("MD5: ");
    //Copy the message into a char array
    char inArray[in.length() + 1];
    in.toCharArray(inArray, in.length() + 1);
    //Create a result array
    uint8_t result[16];
    //Calculate the md5 hash into the result array
    md5(inArray, result);
    //Print the output as hex (arduino built in String hex prints '00' as '0')
    char hex[32];
    for (int i = 0; i < 16; i++) {
      sprintf(hex + 2 * i, "%02x", result[i]);
      Serial.print(hex[2 * i]);
      Serial.print(hex[2 * i + 1]);
    }
    Serial.println();
  }
}

//MD5 Implementation below following the pseudo-code from Wikipedia: https://en.wikipedia.org/wiki/MD5#Pseudocode

const uint32_t s[] = { 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                       5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                       4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                       6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 };

const uint32_t K[64] = {
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
  0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
  0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
  0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
  0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
  0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
  0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

uint32_t leftRotate(uint32_t n, uint32_t offset) {
  return (n << offset) | (n >> (32 - offset));
}

void md5(const char *original_data, uint8_t *result) {

  size_t length = strlen(original_data);
  size_t new_length, offset;

  // Initialize variables A, B, C, D
  uint32_t hash[] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };

  //Calculating length with padding and allocating enough memory
  for (new_length = length + 1; new_length % 64 != 56; new_length++)
    ;
  uint8_t *data = (uint8_t *)calloc(new_length + 8, 1);
  if (data == NULL) return;
  memcpy(data, original_data, length);

  //Pre-processing: adding a single 1 bit
  data[length] = 0x80;

  //Pre-processing: padding with zeros
  //This step is unnecessary as calloc fills the memory with zeros
  //for (offset = length + 1; offset < new_length; offset++)
  //  data[offset] = 0;

  //Pre-processing: append original length in bits
  size_t length_bits = length * 8;
  for (int i = 0; i < 8; i++) {
    data[new_length + i] = (uint8_t)(length_bits >> (8 * i));
  }

  uint32_t M[16];

  //Process the message in successive 512-bit chunks (64 byte)
  for (offset = 0; offset < new_length; offset += 64) {
    //break chunk into sixteen 32-bit words
    for (int i = 0; i < 16; i++) {
      M[i] = (uint32_t)data[offset + i * 4]
             | ((uint32_t)data[offset + i * 4 + 1] << 8)
             | ((uint32_t)data[offset + i * 4 + 2] << 16)
             | ((uint32_t)data[offset + i * 4 + 3] << 24);
    }

    //Initialize hash values for this chunk
    uint32_t a = hash[0];
    uint32_t b = hash[1];
    uint32_t c = hash[2];
    uint32_t d = hash[3];
    uint32_t f, g;

    //Main loop
    for (int i = 0; i < 64; i++) {
      if (i < 16) {
        f = (b & c) | ((~b) & d);
        g = i;
      } else if (i < 32) {
        f = (d & b) | ((~d) & c);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        f = b ^ c ^ d;
        g = (3 * i + 5) % 16;
      } else {
        f = c ^ (b | (~d));
        g = (7 * i) % 16;
      }

      f = f + a + K[i] + M[g];
      a = d;
      d = c;
      c = b;
      b = b + leftRotate(f, s[i]);
    }

    //Add this chunk's hash to result so far:
    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
  }

  free(data);

  //Copy the output to result
  for (int i = 0; i < 4; i++) {
    result[4 * i] = (uint8_t)hash[i];
    result[4 * i + 1] = (uint8_t)(hash[i] >> 8);
    result[4 * i + 2] = (uint8_t)(hash[i] >> 16);
    result[4 * i + 3] = (uint8_t)(hash[i] >> 24);
  }
}