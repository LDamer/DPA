#include "DPA_attacks.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

AESChallenge* scan_data(const char* file, const char* plaintext_file, const unsigned int max_measurements)
{
    //read the plaintexts and store them in an array. later they will be inserted into the datastructure.
    int j = 0;
    int plaintext_array[max_measurements];
    FILE *plaintext = fopen(plaintext_file, "r");
    if(plaintext == NULL)
    {
        printf("failed to read plaintexts");
        return 0;
    }
    char *plain_line = malloc(10);
    while(fgets(plain_line, 10, plaintext) != NULL)
    {
        unsigned int int_token = (unsigned int) strtol(plain_line, NULL, 16);
        plaintext_array[j++] = int_token;
    }
    free(plain_line);
    fclose(plaintext);
    int plaintext_counter = 0;
    AESChallenge *head;
    AESChallenge *previous;
    for(int i = 1; i <= max_measurements; i++)
    {
        AESChallenge *current_challenge_pointer = (AESChallenge *)malloc(sizeof(AESChallenge));

        current_challenge_pointer->challenge = plaintext_array[plaintext_counter++];
        //generate the filename of the trace file.
        char ten = (i%10) + '0';
        char hun = (i/10)%10 + '0';
        char tho = (i/100)%10 + '0';
        char * filename;
        if(tho != '0')
        {
            filename = malloc(12 + 3 + 4 + 1);
            strcpy(filename, file);
            filename[12] = tho;
            filename[13] = hun;
            filename[14] = ten;
            filename[15] = '.';
            filename[16] = 'd';
            filename[17] = 'a';
            filename[18] = 't';
            filename[19] = '\0';
        }
        else if(hun != '0')
        {
            filename = malloc(12 + 2 + 4 + 1);
            strcpy(filename, file);
            filename[12] = hun;
            filename[13] = ten;
            filename[14] = '.';
            filename[15] = 'd';
            filename[16] = 'a';
            filename[17] = 't';
            filename[18] = '\0';
        }
        else
        {
            filename = malloc(12 + 1 + 4 + 1);
            strcpy(filename, file);
            filename[12] = ten;
            filename[13] = '.';
            filename[14] = 'd';
            filename[15] = 'a';
            filename[16] = 't';
            filename[17] = '\0';
        }
        //Read in the traces
        FILE *trace = fopen(filename, "r");
        if(trace == NULL)
        {
            printf("failed to open file %s\n", filename);
            return 0;
        }
        int j = 0;
        char *line = malloc(15);
        char delimiter[] = " ";
        while(fgets(line, 15, trace) != NULL)
        {
            //read time
            char *token = strtok(line, delimiter);
            unsigned int int_token = atoi(token);
            current_challenge_pointer->dTime[j] = int_token;
            //read power
            token = strtok(NULL, delimiter);
            double float_token = (double)atof(token);
            current_challenge_pointer->dPower[j++] = float_token;
            //printf("dTime[%d]=%d;dPower[%d]=%f\n", j-1,current_challenge_pointer->dTime[j-1],j-1,current_challenge_pointer->dPower[j-1]);
        }
        //printf("power[0]=%f\n", current_challenge_pointer->dPower[0]);
        free(line);
        free(filename);
        fclose(trace);
        if(i > 1)
        {
            previous->next = current_challenge_pointer;
        }
        else
        {
            head = current_challenge_pointer;
        }
        // if(i == max_measurements){
        //     current_challenge_pointer->next = 0;
        // }
        previous = current_challenge_pointer;
        //printf("HEAD_1:power: %f\n", current_challenge_pointer->dPower[0]);
    }
    //printf("HEAD_2:power: %f\n", head->dPower[0]);
    return head;
}

MeanAndVar* calculate_mean_var(const AESChallenge* challenge, const unsigned int max_measurements)
{
    MeanAndVar * mv = (MeanAndVar*)malloc(sizeof(MeanAndVar));
    AESChallenge * current_challenge = challenge;
    // calculate mean and variance here
    for(; current_challenge->next != 0; current_challenge = current_challenge->next) //mean
    {
        for(int i = 0; i < 100; i++)
        {
            mv->dMean[i] += current_challenge->dPower[i]/max_measurements;
        }
    }
    //variance
    current_challenge = challenge;
    for(; current_challenge->next != 0; current_challenge = current_challenge->next) //variance
    {
        for(int i = 0; i < 100; i++)
        {
            mv->dVar[i] += ((current_challenge->dPower[i] - mv->dMean[i])*(current_challenge->dPower[i] - mv->dMean[i]))/max_measurements;
        }
    }
    /*
    FILE * meanFile = fopen("mean.txt", "w");
    FILE * varFile = fopen("var.txt", "w");
    if(varFile == NULL || meanFile == NULL)printf("failed to load files!");
    for(int i = 0; i < 100; i++){
        fprintf(meanFile, "%f\n", mv->dMean[i]);
        fprintf(varFile, "%f\n", mv->dVar[i]);
    }
    fclose(meanFile);
    fclose(varFile);
    */
    return mv;
}


unsigned char getSboxOut(unsigned char input, unsigned char key)
{
    unsigned char Sbox[256] =
    {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
        0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
        0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
        0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
        0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
        0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
        0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
        0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
        0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
        0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
        0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
        0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
        0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };


    // insert your code here
    char sbox_in = input ^ key;
    return Sbox[sbox_in];
}

unsigned char getHW(unsigned char b)
{
    // insert your code here
    unsigned char hw = 0;
    for(int i = 0; i < 8; i++)
    {
        if(b%2!=0)
        {
            hw += 1;
        }
        b /= 2;
    }
    // return Hamming weight of B
    return hw;
}


unsigned char DiffOfMeans_attack(const AESChallenge* challenge,  const unsigned int max_measurements)
{
    // insert your code for the Difference of Means DPA here
    AESChallenge * head;//copy challenge pointer
    char current_best_key = -1;
    double max_val_for_best_key = -1.0;
    for(int key = 0; key < 256; key++)
    {
        head = challenge;//start at the head of the list
        AESChallenge* p1[max_measurements];
        AESChallenge* p2[max_measurements];
        int counterP1 = 0;
        int counterP2 = 0;
        //calculate HW and store the challenges in either p1 or p2
        //while(head->next != 0){
        for(; head->next != 0; head = head->next)
        {
            char b0 = getSboxOut((unsigned char)head->challenge, key);
            char hw = getHW(b0);
            if(hw < 4)
            {
                p1[counterP1++] = head;
            }
            else
            {
                p2[counterP2++] = head;
            }
        }
        //calculate the mean of the two sets
        //mean of p1
        double * meanP1 = malloc(sizeof(double) * 100);
        for(int i = 0; i < counterP1; i++) //iterate through P1
        {
            for(int j = 0; j < 100; j++) //itereate through points on current trace
            {
                meanP1[j] += (p1[i]->dPower[j])/(counterP1);
            }
        }
        //mean of p2
        double * meanP2 = malloc(sizeof(double) * 100);
        for(int i = 0; i < counterP2; i++) //iterate through P2
        {
            for(int j = 0; j < 100; j++) //itereate through points on current trace
            {
                meanP2[j] += (p2[i]->dPower[j])/(counterP2);
            }
        }

        //calculate the difference (absolut values) of the means and store them in P1.
        for(int i = 0; i < 100; i++)
        {
            //printf("meanP1[%i]=%f - meanP2[%d]=%f  =  %f\n",i,meanP1[i], i,meanP2[i],meanP1[i] - meanP2[i]);
            meanP1[i] = meanP1[i] - meanP2[i];
            if(meanP1[i] < 0)
            {
                meanP1[i] = -meanP1[i];
            }
        }
        //find biggest difference and compare if its better than the max_val_for_best_key
        for(int i = 0; i < 100; i++)
        {
            if(meanP1[i] > max_val_for_best_key)
            {
                max_val_for_best_key = meanP1[i];
                current_best_key = key;
            }
        }

    }

    // return the most probabale key guess
    return current_best_key;
}








