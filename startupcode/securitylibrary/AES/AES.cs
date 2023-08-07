﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    class AES_Constants
    {
        public static int[] RCON = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

        public static int[,] MIX ={
                                   {0x02,0x03,0x01,0x01},
                                   {0x01,0x02,0x03,0x01},
                                   {0x01,0x01,0x02,0x03},
                                   {0x03,0x01,0x01,0x02}};
        public static int[,] MIX_INV ={
                                    {0x0E,0x0B,0x0D,0x09},
                                    {0x09,0x0E,0x0B,0x0D},
                                    {0x0D,0x09,0x0E,0x0B},
                                    {0x0B,0x0D,0x09,0x0E}};
        public static int[,] S_BOX ={
    {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
    {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
    {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
    {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
    {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
    {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
    {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
    {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
    {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
    {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
    {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
    {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
    {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
    {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
    {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
    {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}};


        public static int[,] S_BOX_INVERS ={
    {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
    {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
    {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
    {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
    {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
    {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
    {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
    {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
    {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
    {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
    {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
    {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
    {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
    {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
    {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}};

        public static int[,] L ={
                             {0x00,0x00,0x19,0x01,0x32,0x02,0x1A,0xC6,0x4B,0xC7,0x1B,0x68,0x33,0xEE,0xDF,0x03},
                             {0x64,0x04,0xE0,0x0E,0x34,0x8D,0x81,0xEF,0x4C,0x71,0x08,0xC8,0xF8,0x69,0x1C,0xC1},
                             {0x7D,0xC2,0x1D,0xB5,0xF9,0xB9,0x27,0x6A,0x4D,0xE4,0xA6,0x72,0x9A,0xC9,0x09,0x78},
                             {0x65,0x2F,0x8A,0x05,0x21,0x0F,0xE1,0x24,0x12,0xF0,0x82,0x45,0x35,0x93,0xDA,0x8E},
                             {0x96,0x8F,0xDB,0xBD,0x36,0xD0,0xCE,0x94,0x13,0x5C,0xD2,0xF1,0x40,0x46,0x83,0x38},
                             {0x66,0xDD,0xFD,0x30,0xBF,0x06,0x8B,0x62,0xB3,0x25,0xE2,0x98,0x22,0x88,0x91,0x10},
                             {0x7E,0x6E,0x48,0xC3,0xA3,0xB6,0x1E,0x42,0x3A,0x6B,0x28,0x54,0xFA,0x85,0x3D,0xBA},
                             {0x2B,0x79,0x0A,0x15,0x9B,0x9F,0x5E,0xCA,0x4E,0xD4,0xAC,0xE5,0xF3,0x73,0xA7,0x57},
                             {0xAF,0x58,0xA8,0x50,0xF4,0xEA,0xD6,0x74,0x4F,0xAE,0xE9,0xD5,0xE7,0xE6,0xAD,0xE8},
                             {0x2C,0xD7,0x75,0x7A,0xEB,0x16,0x0B,0xF5,0x59,0xCB,0x5F,0xB0,0x9C,0xA9,0x51,0xA0},
                             {0x7F,0x0C,0xF6,0x6F,0x17,0xC4,0x49,0xEC,0xD8,0x43,0x1F,0x2D,0xA4,0x76,0x7B,0xB7},
                             {0xCC,0xBB,0x3E,0x5A,0xFB,0x60,0xB1,0x86,0x3B,0x52,0xA1,0x6C,0xAA,0x55,0x29,0x9D},
                             {0x97,0xB2,0x87,0x90,0x61,0xBE,0xDC,0xFC,0xBC,0x95,0xCF,0xCD,0x37,0x3F,0x5B,0xD1},
                             {0x53,0x39,0x84,0x3C,0x41,0xA2,0x6D,0x47,0x14,0x2A,0x9E,0x5D,0x56,0xF2,0xD3,0xAB},
                             {0x44,0x11,0x92,0xD9,0x23,0x20,0x2E,0x89,0xB4,0x7C,0xB8,0x26,0x77,0x99,0xE3,0xA5},
                             {0x67,0x4A,0xED,0xDE,0xC5,0x31,0xFE,0x18,0x0D,0x63,0x8C,0x80,0xC0,0xF7,0x70,0x07}
                         };
        public static int[,] E ={
                          { 0x01,0x03,0x05,0x0F,0x11,0x33,0x55,0xFF,0x1A,0x2E,0x72,0x96,0xA1,0xF8,0x13,0x35},
                          { 0x5F,0xE1,0x38,0x48,0xD8,0x73,0x95,0xA4,0xF7,0x02,0x06,0x0A,0x1E,0x22,0x66,0xAA},
                          { 0xE5,0x34,0x5C,0xE4,0x37,0x59,0xEB,0x26,0x6A,0xBE,0xD9,0x70,0x90,0xAB,0xE6,0x31},
                          { 0x53,0xF5,0x04,0x0C,0x14,0x3C,0x44,0xCC,0x4F,0xD1,0x68,0xB8,0xD3,0x6E,0xB2,0xCD},
                          { 0x4C,0xD4,0x67,0xA9,0xE0,0x3B,0x4D,0xD7,0x62,0xA6,0xF1,0x08,0x18,0x28,0x78,0x88},
                          { 0x83,0x9E,0xB9,0xD0,0x6B,0xBD,0xDC,0x7F,0x81,0x98,0xB3,0xCE,0x49,0xDB,0x76,0x9A},
                          { 0xB5,0xC4,0x57,0xF9,0x10,0x30,0x50,0xF0,0x0B,0x1D,0x27,0x69,0xBB,0xD6,0x61,0xA3},
                          { 0xFE,0x19,0x2B,0x7D,0x87,0x92,0xAD,0xEC,0x2F,0x71,0x93,0xAE,0xE9,0x20,0x60,0xA0},
                          { 0xFB,0x16,0x3A,0x4E,0xD2,0x6D,0xB7,0xC2,0x5D,0xE7,0x32,0x56,0xFA,0x15,0x3F,0x41},
                          { 0xC3,0x5E,0xE2,0x3D,0x47,0xC9,0x40,0xC0,0x5B,0xED,0x2C,0x74,0x9C,0xBF,0xDA,0x75},
                          { 0x9F,0xBA,0xD5,0x64,0xAC,0xEF,0x2A,0x7E,0x82,0x9D,0xBC,0xDF,0x7A,0x8E,0x89,0x80},
                          { 0x9B,0xB6,0xC1,0x58,0xE8,0x23,0x65,0xAF,0xEA,0x25,0x6F,0xB1,0xC8,0x43,0xC5,0x54},
                          { 0xFC,0x1F,0x21,0x63,0xA5,0xF4,0x07,0x09,0x1B,0x2D,0x77,0x99,0xB0,0xCB,0x46,0xCA},
                          { 0x45,0xCF,0x4A,0xDE,0x79,0x8B,0x86,0x91,0xA8,0xE3,0x3E,0x42,0xC6,0x51,0xF3,0x0E},
                          { 0x12,0x36,0x5A,0xEE,0x29,0x7B,0x8D,0x8C,0x8F,0x8A,0x85,0x94,0xA7,0xF2,0x0D,0x17},
                          { 0x39,0x4B,0xDD,0x7C,0x84,0x97,0xA2,0xFD,0x1C,0x24,0x6C,0xB4,0xC7,0x52,0xF6,0x01}
                        };

    }
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        public static byte[] RCON = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

        public static byte[,] MIX ={
                                   {0x02,0x03,0x01,0x01},
                                   {0x01,0x02,0x03,0x01},
                                   {0x01,0x01,0x02,0x03},
                                   {0x03,0x01,0x01,0x02}};
        public static byte[,] MIX_INV ={
                                    {0x0E,0x0B,0x0D,0x09},
                                    {0x09,0x0E,0x0B,0x0D},
                                    {0x0D,0x09,0x0E,0x0B},
                                    {0x0B,0x0D,0x09,0x0E}};
        public static byte[,] S_BOX ={
    {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
    {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
    {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
    {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
    {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
    {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
    {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
    {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
    {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
    {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
    {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
    {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
    {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
    {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
    {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
    {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}};


        public static byte[,] S_BOX_INVERS ={
    {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
    {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
    {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
    {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
    {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
    {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
    {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
    {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
    {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
    {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
    {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
    {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
    {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
    {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
    {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}};

        public static byte[,] L ={
                             {0x00,0x00,0x19,0x01,0x32,0x02,0x1A,0xC6,0x4B,0xC7,0x1B,0x68,0x33,0xEE,0xDF,0x03},
                             {0x64,0x04,0xE0,0x0E,0x34,0x8D,0x81,0xEF,0x4C,0x71,0x08,0xC8,0xF8,0x69,0x1C,0xC1},
                             {0x7D,0xC2,0x1D,0xB5,0xF9,0xB9,0x27,0x6A,0x4D,0xE4,0xA6,0x72,0x9A,0xC9,0x09,0x78},
                             {0x65,0x2F,0x8A,0x05,0x21,0x0F,0xE1,0x24,0x12,0xF0,0x82,0x45,0x35,0x93,0xDA,0x8E},
                             {0x96,0x8F,0xDB,0xBD,0x36,0xD0,0xCE,0x94,0x13,0x5C,0xD2,0xF1,0x40,0x46,0x83,0x38},
                             {0x66,0xDD,0xFD,0x30,0xBF,0x06,0x8B,0x62,0xB3,0x25,0xE2,0x98,0x22,0x88,0x91,0x10},
                             {0x7E,0x6E,0x48,0xC3,0xA3,0xB6,0x1E,0x42,0x3A,0x6B,0x28,0x54,0xFA,0x85,0x3D,0xBA},
                             {0x2B,0x79,0x0A,0x15,0x9B,0x9F,0x5E,0xCA,0x4E,0xD4,0xAC,0xE5,0xF3,0x73,0xA7,0x57},
                             {0xAF,0x58,0xA8,0x50,0xF4,0xEA,0xD6,0x74,0x4F,0xAE,0xE9,0xD5,0xE7,0xE6,0xAD,0xE8},
                             {0x2C,0xD7,0x75,0x7A,0xEB,0x16,0x0B,0xF5,0x59,0xCB,0x5F,0xB0,0x9C,0xA9,0x51,0xA0},
                             {0x7F,0x0C,0xF6,0x6F,0x17,0xC4,0x49,0xEC,0xD8,0x43,0x1F,0x2D,0xA4,0x76,0x7B,0xB7},
                             {0xCC,0xBB,0x3E,0x5A,0xFB,0x60,0xB1,0x86,0x3B,0x52,0xA1,0x6C,0xAA,0x55,0x29,0x9D},
                             {0x97,0xB2,0x87,0x90,0x61,0xBE,0xDC,0xFC,0xBC,0x95,0xCF,0xCD,0x37,0x3F,0x5B,0xD1},
                             {0x53,0x39,0x84,0x3C,0x41,0xA2,0x6D,0x47,0x14,0x2A,0x9E,0x5D,0x56,0xF2,0xD3,0xAB},
                             {0x44,0x11,0x92,0xD9,0x23,0x20,0x2E,0x89,0xB4,0x7C,0xB8,0x26,0x77,0x99,0xE3,0xA5},
                             {0x67,0x4A,0xED,0xDE,0xC5,0x31,0xFE,0x18,0x0D,0x63,0x8C,0x80,0xC0,0xF7,0x70,0x07}
                         };
        public static byte[,] E ={
                          { 0x01,0x03,0x05,0x0F,0x11,0x33,0x55,0xFF,0x1A,0x2E,0x72,0x96,0xA1,0xF8,0x13,0x35},
                          { 0x5F,0xE1,0x38,0x48,0xD8,0x73,0x95,0xA4,0xF7,0x02,0x06,0x0A,0x1E,0x22,0x66,0xAA},
                          { 0xE5,0x34,0x5C,0xE4,0x37,0x59,0xEB,0x26,0x6A,0xBE,0xD9,0x70,0x90,0xAB,0xE6,0x31},
                          { 0x53,0xF5,0x04,0x0C,0x14,0x3C,0x44,0xCC,0x4F,0xD1,0x68,0xB8,0xD3,0x6E,0xB2,0xCD},
                          { 0x4C,0xD4,0x67,0xA9,0xE0,0x3B,0x4D,0xD7,0x62,0xA6,0xF1,0x08,0x18,0x28,0x78,0x88},
                          { 0x83,0x9E,0xB9,0xD0,0x6B,0xBD,0xDC,0x7F,0x81,0x98,0xB3,0xCE,0x49,0xDB,0x76,0x9A},
                          { 0xB5,0xC4,0x57,0xF9,0x10,0x30,0x50,0xF0,0x0B,0x1D,0x27,0x69,0xBB,0xD6,0x61,0xA3},
                          { 0xFE,0x19,0x2B,0x7D,0x87,0x92,0xAD,0xEC,0x2F,0x71,0x93,0xAE,0xE9,0x20,0x60,0xA0},
                          { 0xFB,0x16,0x3A,0x4E,0xD2,0x6D,0xB7,0xC2,0x5D,0xE7,0x32,0x56,0xFA,0x15,0x3F,0x41},
                          { 0xC3,0x5E,0xE2,0x3D,0x47,0xC9,0x40,0xC0,0x5B,0xED,0x2C,0x74,0x9C,0xBF,0xDA,0x75},
                          { 0x9F,0xBA,0xD5,0x64,0xAC,0xEF,0x2A,0x7E,0x82,0x9D,0xBC,0xDF,0x7A,0x8E,0x89,0x80},
                          { 0x9B,0xB6,0xC1,0x58,0xE8,0x23,0x65,0xAF,0xEA,0x25,0x6F,0xB1,0xC8,0x43,0xC5,0x54},
                          { 0xFC,0x1F,0x21,0x63,0xA5,0xF4,0x07,0x09,0x1B,0x2D,0x77,0x99,0xB0,0xCB,0x46,0xCA},
                          { 0x45,0xCF,0x4A,0xDE,0x79,0x8B,0x86,0x91,0xA8,0xE3,0x3E,0x42,0xC6,0x51,0xF3,0x0E},
                          { 0x12,0x36,0x5A,0xEE,0x29,0x7B,0x8D,0x8C,0x8F,0x8A,0x85,0x94,0xA7,0xF2,0x0D,0x17},
                          { 0x39,0x4B,0xDD,0x7C,0x84,0x97,0xA2,0xFD,0x1C,0x24,0x6C,0xB4,0xC7,0x52,0xF6,0x01}
                        };
        private static int[,] generateNewKey(int[,] keyMatrix, int[,] subsMatrix, int roundNum)
        {
            int[,] newKeyMatrix = new int[4, 4];
            int[] lastCol = new int[4];

            // Get the last column from the keyMatrix
            for (int i = 0; i < 4; i++)
            {
                lastCol[i] = keyMatrix[i, 3];
            }

            // Rotate the last column
            int temp = lastCol[0];
            for (int i = 1; i < 4; i++)
            {
                lastCol[i - 1] = lastCol[i];
            }
            lastCol[3] = temp;

            // Substitute each byte in the last column using subsMatrix
            for (int i = 0; i < 4; i++)
            {
                lastCol[i] = subsMatrix[((lastCol[i] & 240) >> 4), (lastCol[i] & 15)];
            }

            // XOR the first byte in the last column with RCON[roundNum]
            lastCol[0] = lastCol[0] ^ AES_Constants.RCON[roundNum];

            // Generate the new key matrix
            for (int i = 0; i < 4; i++)
            {
                newKeyMatrix[i, 0] = keyMatrix[i, 0] ^ lastCol[i];
            }

            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    newKeyMatrix[j, i] = newKeyMatrix[j, i - 1] ^ keyMatrix[j, i];
                }
            }

            return newKeyMatrix;
        }
        private static int[,] substituteRound(int[,] kXorPt, int[,] subsMatrix)
        {
            int[,] res = new int[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int upperNibble = (kXorPt[i, j] & 0xF0) >> 4;
                    int lowerNibble = kXorPt[i, j] & 0x0F;
                    res[i, j] = subsMatrix[upperNibble, lowerNibble];
                }
            }
            return res;
        }

        private static int[,] MixColumns(int[,] stateMatrix, int[,] constMatrix)
        {
            int[,] result = new int[4, 4];

            for (int j = 0; j < 4; j++)
            {
                int[] column = new int[4];

                // Copy the current column of the state matrix into an array
                for (int i = 0; i < 4; i++)
                {
                    column[i] = stateMatrix[i, j];
                }

                // Perform the matrix multiplication
                for (int i = 0; i < 4; i++)
                {
                    int sum = 0;

                    for (int k = 0; k < 4; k++)
                    {
                        int term = Multiply(column[k], constMatrix[i, k]);
                        sum ^= term;
                    }

                    result[i, j] = sum;
                }
            }

            return result;
        }
        private static int Multiply(int a, int b)
        {
            int p = 0;

            for (int i = 0; i < 8; i++)
            {
                if ((b & 1) != 0)
                {
                    p ^= a;
                }

                bool carry = (a & 0x80) != 0;
                a <<= 1;

                if (carry)
                {
                    a ^= 0x1B;  // irreducible polynomial x^8 + x^4 + x^3 + x + 1
                }

                b >>= 1;
            }

            return p;
        }
        private static int[,] addRoundKey(int[,] state, int[,] roundKey)
        {
            int[,] result = new int[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result[i, j] = state[i, j] ^ roundKey[i, j];
                }
            }

            return result;
        }
        private static int[,] hexToInt(string hex)
        {
            int[,] res = new int[4, 4];
            int counter = 0;
            hex = hex.Substring(2);
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++, counter += 2)
                    res[j, i] = Convert.ToInt32(hex.Substring(counter, 2), 16);

            return res;
        }
        private static int[,] shiftRowsInvers(int[,] state)
        {
            int[,] result = new int[4, 4];

            // first row is not shifted
            result[0, 0] = state[0, 0];
            result[0, 1] = state[0, 1];
            result[0, 2] = state[0, 2];
            result[0, 3] = state[0, 3];

            // second row is shifted by 1
            result[1, 0] = state[1, 3];
            result[1, 1] = state[1, 0];
            result[1, 2] = state[1, 1];
            result[1, 3] = state[1, 2];

            // third row is shifted by 2
            result[2, 0] = state[2, 2];
            result[2, 1] = state[2, 3];
            result[2, 2] = state[2, 0];
            result[2, 3] = state[2, 1];

            // fourth row is shifted by 3
            result[3, 0] = state[3, 1];
            result[3, 1] = state[3, 2];
            result[3, 2] = state[3, 3];
            result[3, 3] = state[3, 0];

            return result;
        }

        public override string Decrypt(string cipherText, string key)
        {
            int[,] pTMatrix = hexToInt(cipherText);

            int[,] keyMatrix = hexToInt(key);

            int[][,] keyGenrated = new int[10][,];

            keyGenrated[0] = generateNewKey(keyMatrix, AES_Constants.S_BOX, 1);

            for (int i = 1; i < 10; i++)
            {
                keyGenrated[i] = generateNewKey(keyGenrated[i - 1], AES_Constants.S_BOX, i + 1);
            }

            pTMatrix = addRoundKey(pTMatrix, keyGenrated[9]);

            for (int i = 8; i >= 0; i--)
            {

                pTMatrix = shiftRowsInvers(pTMatrix);

                pTMatrix = substituteRound(pTMatrix, AES_Constants.S_BOX_INVERS);
                pTMatrix = addRoundKey(pTMatrix, keyGenrated[i]);
                pTMatrix = MixColumns(pTMatrix, AES_Constants.MIX_INV);

            }
            pTMatrix = shiftRowsInvers(pTMatrix);
            pTMatrix = substituteRound(pTMatrix, AES_Constants.S_BOX_INVERS);
            keyMatrix = hexToInt(key);
            pTMatrix = addRoundKey(pTMatrix, keyMatrix);
            string res = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string e = pTMatrix[j, i].ToString("X");
                    if (e.Length < 2)
                        e = "0" + e;
                    res += e;
                }
            }
            return "0x" + res;

        }



       

        public override string   Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            //round 0
            plainText=plainText.Substring(2,plainText.Length - 2);
            key=key.Substring(2,key.Length - 2);
            string newKey = key;
            string round0 = AddRoundKey(plainText, key);

            //next 9 rounds
            for (int i = 1; i < 10; i++)
            {

                string subByteResult = subBytes(round0);
                
                string[,] shiftRowsResult = shiftrows(subByteResult);
             
                string[,] mixColumnsResult = mixColumns(shiftRowsResult);
              
                newKey = generateKey(newKey, i);
              
                string newmixColumnsResult = convertFrom2dToString(mixColumnsResult);
               

                string AddRoundKeyResult = AddRoundKey(newmixColumnsResult, newKey);
             
                round0 = AddRoundKeyResult;

            
            }
            //last round
            string lastSub = subBytes(round0);
            string[,] lastShift = shiftrows(lastSub);
            string lastgeneration = generateKey(newKey, 10);
            string lastAdd = AddRoundKey(convertFrom2dToString(lastShift), lastgeneration);
            return "0x"+lastAdd.ToUpper();
        }
        public static string subBytes(string roundedKey)
        {
            string result = "";
            for (int i = 0; i < 32; i = i + 2)
            {
                string substring = roundedKey.Substring(i, 2);
                int row = Convert.ToInt32(substring[0].ToString(), 16); // convert character to integer
                int column = Convert.ToInt32(substring[1].ToString(), 16); // convert character to integer   
                                                                           //access the values in the sbox matrix
                result += AES_Constants.S_BOX[row, column].ToString("x2");
            }
            return result;
        }
        public static byte[] rotateColumn(byte[] column)
        {
            byte tmp = column[0];

            for (int i = 0; i < 3; i++)
                column[i] = column[i + 1];

            column[3] = tmp;
            return column;
        }
        
        public static string convertFrom2dToString(string[,] input)
        {
            int n = input.GetLength(0);
            string output = "";
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < n; j++)
                {

                    output += input[j, i];
                }
            }
            return output;
        }
        public static string generateKey(string key, int roundNum)
        {
            string[,] keyMatrix = ConvertTo2DStringMatrix1(key);
            byte[,] keyMatrixByte = ConvertToByteMatrix(keyMatrix);
            byte[,] newKeyMatrix = new byte[4, 4];
            byte[] lastCol = new byte[4];

            // Get the last column from the keyMatrix
            for (int i = 0; i < 4; i++)
            {
                lastCol[i] = keyMatrixByte[i, 3];
            }
            lastCol = rotateColumn(lastCol);

            //subistitute 
            for (int i = 0; i < 4; i++)
            {
                lastCol[i] = (byte)(S_BOX[(lastCol[i] & 240) >> 4, lastCol[i] & 15]);
            }
            //xor
            lastCol[0] = (byte)(lastCol[0] ^ AES_Constants.RCON[roundNum]);
            // Generate the new key matrix
            for (int i = 0; i < 4; i++)
            {
                newKeyMatrix[i, 0] = (byte)(keyMatrixByte[i, 0] ^ lastCol[i]);
            }

            for (int i = 1; i < 4; i++)
                for (int j = 0; j < 4; j++)
                {

                    {
                        newKeyMatrix[j, i] = (byte)(newKeyMatrix[j, i - 1] ^ keyMatrixByte[j, i]);
                    }
                }

            return ConvertToString(newKeyMatrix);

        }
        public static string[,] ConvertTo2DStringMatrix1(string input)
        {
            int n = (int)Math.Sqrt(input.Length / 2);
            string[,] output = new string[n, n];
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    int startIndex = (i * n + j) * 2;
                    output[j, i] = input.Substring(startIndex, 2);
                }
            }
            return output;
        }


        public static string AddRoundKey(string plain, string key)
        {

            string hexResult = "";
            int i;
            for (i = 0; i < 32; i = i + 2)
            {
                string sub1 = plain.Substring(i, 2);
                string sub2 = key.Substring(i, 2);


                int int1 = Convert.ToInt32(sub1, 16);
                int int2 = Convert.ToInt32(sub2, 16);

                hexResult += (int1 ^ int2).ToString("x2");

            }

            return hexResult;
        }

        public static string[,] shiftrows(string roundedKey)
        {
            string[,] x = new string[4, 4];
            int counter = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    x[j, i] = roundedKey.Substring(counter, 2);
                    counter = counter + 2;
                }
            }


            for (int i = 1; i < 4; i++)
            {
                int shift = i;
                for (int j = 0; j < shift; j++)
                {
                    string temp = x[i, 0].Substring(0, 2);//row by row 
                    for (int k = 1; k < 4; k++)
                    {
                        x[i, k - 1] = x[i, k];
                    }
                    x[i, 3] = temp;
                }
            }

            return x;
        }
        public static string[,] mixColumns(string[,] plain)
        {
            byte[,] result = ConvertToByteMatrix(plain);
            byte[,] result2 = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    byte sub = 0x00;
                    for (int k = 0; k < 4; k++)
                    {
                        byte tmp = 0x00;
                        if (AES_Constants.MIX[i, k] == 0x01)//multiply by one do nothing 
                        {
                            tmp = result[k, j];
                        }
                        else if (AES_Constants.MIX[i, k] == 0x03)
                        {
                            tmp = (byte)(result[k, j] << 1);
                            if ((byte)(result[k, j] & 0x80) == 0x80)
                            {
                                tmp = (byte)(tmp ^ 0x1b);

                            }
                            tmp = (byte)(tmp ^ result[k, j]);
                        }
                        else //multiply by 2 
                        {
                            tmp = (byte)(result[k, j] << 1);
                            if ((byte)(result[k, j] & 0x80) == 0x80)
                            {
                                tmp = (byte)(tmp ^ 0x1b);

                            }
                        }

                        sub = (byte)(sub ^ tmp);
                    }
                    result2[i, j] = sub;
                }
            }
            string[,] result3 = ConvertToStringMatrix(result2);
            return result3;

        }
        public static byte[,] ConvertToByteMatrix(string[,] input)
        {
            int n = input.GetLength(0);
            int m = input.GetLength(1);
            byte[,] output = new byte[n, m];
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    output[i, j] = Convert.ToByte(input[i, j], 16);
                }
            }
            return output;
        }
        //done

        public static string[,] ConvertToStringMatrix(byte[,] input)
        {
            int n = input.GetLength(0);
            int m = input.GetLength(1);
            string[,] output = new string[n, m];
            for (int i = 0; i < n; i++)
                for (int j = 0; j < m; j++)
                    output[i, j] = input[i, j].ToString("x2");
            return output;
        }
        public static string ConvertToString(byte[,] input)
        {
            int n = input.GetLength(0);
            int m = input.GetLength(1);
            string[,] output = new string[n, m];
            for (int i = 0; i < n; i++)
                for (int j = 0; j < m; j++)
                    output[i, j] = input[i, j].ToString("x2");
            string strOutput = "";
            for (int i = 0; i < output.GetLength(0); i++)
            {
                for (int j = 0; j < output.GetLength(1); j++)
                {
                    strOutput += output[j, i];
                }
            }
            return strOutput;
        }


    }
}




