#ifndef _ATTACKS_H
#define _ATTACKS_H

#include <stdio.h>
#include <gmp.h>
#include <math.h>

#define TRACELENGTH 100

/**
 * Struct storing the challenge data as linked list
 */
typedef struct _AESChallenge {
  unsigned int challenge; /*!< AES challenge */
  double dPower[TRACELENGTH]; /*!< power consumption trace */
  unsigned int dTime[TRACELENGTH]; /*!< corresponding time */
  struct _AESChallenge * next; /*!< next node, or 0 if tail */
} AESChallenge; 


/**
 * Struct storing mean and variance of a trace
 */
typedef struct {
  double dMean[TRACELENGTH]; /*!< mean trace */
  double dVar[TRACELENGTH]; /*!< variance trace */
} MeanAndVar; 


/**
 * Function scanning challenges from a file
 * @param file Filename of first file to read in 
 * @param max_measurements Upper bound for measurements to read 
 * @return pointer to data list head on success, 0 on failure/not implemented
 */  
AESChallenge* scan_data(const char* file, const char* plaintext_file, const unsigned int max_measurements);

/**
 * Function for generating mean and variance trace
 * @param challenge Pointer to head of the AES challenge list
 * @param max_measurements Upper bound for measurements to read 
 * @return pointer to data struct on success, 0 on failure/not implemented
 */ 
MeanAndVar* calculate_mean_var(const AESChallenge* challenge, const unsigned int max_measurements);

/**
 * generate sbox output
 * @param input known challenge
 * @param key the guessed key
 * @return output of sbox 
 */
unsigned char getSboxOut(unsigned char input, unsigned char key);


/**
 * get hamming weight
 * @param b Parameter whose hamming weight is to be determined
 * @return Hamming weight of b
 */
unsigned char getHW(unsigned char b);


/**
 * Difference of Means Attack
 * @param challenge Pointer to head of the AES challenge list
 * @param max_measurements Upper bound for measurements to read 
 * @return most probable key candidate
 */
unsigned char DiffOfMeans_attack(const AESChallenge* challenge,  const unsigned int max_measurements);

/**
 * Correlation Attack
 * @param challenge Pointer to head of the AES challenge list
 * @param MeanVarTrace mean and variance of power traces
 * @param max_measurements Upper bound for measurements to read 
 * @return most probable key candidate
 */
unsigned char correlation_attack(const AESChallenge* challenge, const MeanAndVar * MeanVarTrace,  const unsigned int max_measurements);


#endif
