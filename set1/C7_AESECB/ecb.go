package main

import (
	"errors"
	"fmt"
	"github.com/weltan/cryptochallenges/utils"
	"log"
)

const cipherFileName = "/Users/ken/code/src/github.com/weltan/cryptochallenges/set1/C7_AESECB/7.txt"
const cipherFileNameWin = "C:/Users/Ken/Documents/code/src/github.com/weltan/cryptochallenges/set1/C7_AESECB/7.txt"

// Nk AES-128 key length (in words)
var aes128KeySize = 4
var aes192KeySize = 6
var aes256KeySize = 8

// Nb AES block size (in words)
const aesBlockSize = 4

// Nr AES-128 number of rounds
var aes128Rounds = 10
var aes192Rounds = 12
var aes256Rounds = 14

var sbox = [256]byte{
	'\x63', '\x7C', '\x77', '\x7B', '\xF2', '\x6B', '\x6F', '\xC5', '\x30', '\x01', '\x67', '\x2B', '\xFE', '\xD7', '\xAB', '\x76',
	'\xCA', '\x82', '\xC9', '\x7D', '\xFA', '\x59', '\x47', '\xF0', '\xAD', '\xD4', '\xA2', '\xAF', '\x9C', '\xA4', '\x72', '\xC0',
	'\xB7', '\xFD', '\x93', '\x26', '\x36', '\x3F', '\xF7', '\xCC', '\x34', '\xA5', '\xE5', '\xF1', '\x71', '\xD8', '\x31', '\x15',
	'\x04', '\xC7', '\x23', '\xC3', '\x18', '\x96', '\x05', '\x9A', '\x07', '\x12', '\x80', '\xE2', '\xEB', '\x27', '\xB2', '\x75',
	'\x09', '\x83', '\x2C', '\x1A', '\x1B', '\x6E', '\x5A', '\xA0', '\x52', '\x3B', '\xD6', '\xB3', '\x29', '\xE3', '\x2F', '\x84',
	'\x53', '\xD1', '\x00', '\xED', '\x20', '\xFC', '\xB1', '\x5B', '\x6A', '\xCB', '\xBE', '\x39', '\x4A', '\x4C', '\x58', '\xCF',
	'\xD0', '\xEF', '\xAA', '\xFB', '\x43', '\x4D', '\x33', '\x85', '\x45', '\xF9', '\x02', '\x7F', '\x50', '\x3C', '\x9F', '\xA8',
	'\x51', '\xA3', '\x40', '\x8F', '\x92', '\x9D', '\x38', '\xF5', '\xBC', '\xB6', '\xDA', '\x21', '\x10', '\xFF', '\xF3', '\xD2',
	'\xCD', '\x0C', '\x13', '\xEC', '\x5F', '\x97', '\x44', '\x17', '\xC4', '\xA7', '\x7E', '\x3D', '\x64', '\x5D', '\x19', '\x73',
	'\x60', '\x81', '\x4F', '\xDC', '\x22', '\x2A', '\x90', '\x88', '\x46', '\xEE', '\xB8', '\x14', '\xDE', '\x5E', '\x0B', '\xDB',
	'\xE0', '\x32', '\x3A', '\x0A', '\x49', '\x06', '\x24', '\x5C', '\xC2', '\xD3', '\xAC', '\x62', '\x91', '\x95', '\xE4', '\x79',
	'\xE7', '\xC8', '\x37', '\x6D', '\x8D', '\xD5', '\x4E', '\xA9', '\x6C', '\x56', '\xF4', '\xEA', '\x65', '\x7A', '\xAE', '\x08',
	'\xBA', '\x78', '\x25', '\x2E', '\x1C', '\xA6', '\xB4', '\xC6', '\xE8', '\xDD', '\x74', '\x1F', '\x4B', '\xBD', '\x8B', '\x8A',
	'\x70', '\x3E', '\xB5', '\x66', '\x48', '\x03', '\xF6', '\x0E', '\x61', '\x35', '\x57', '\xB9', '\x86', '\xC1', '\x1D', '\x9E',
	'\xE1', '\xF8', '\x98', '\x11', '\x69', '\xD9', '\x8E', '\x94', '\x9B', '\x1E', '\x87', '\xE9', '\xCE', '\x55', '\x28', '\xDF',
	'\x8C', '\xA1', '\x89', '\x0D', '\xBF', '\xE6', '\x42', '\x68', '\x41', '\x99', '\x2D', '\x0F', '\xB0', '\x54', '\xBB', '\x16'}

var invSbox = [256]byte{
	'\x52', '\x09', '\x6A', '\xD5', '\x30', '\x36', '\xA5', '\x38', '\xBF', '\x40', '\xA3', '\x9E', '\x81', '\xF3', '\xD7', '\xFB',
	'\x7C', '\xE3', '\x39', '\x82', '\x9B', '\x2F', '\xFF', '\x87', '\x34', '\x8E', '\x43', '\x44', '\xC4', '\xDE', '\xE9', '\xCB',
	'\x54', '\x7B', '\x94', '\x32', '\xA6', '\xC2', '\x23', '\x3D', '\xEE', '\x4C', '\x95', '\x0B', '\x42', '\xFA', '\xC3', '\x4E',
	'\x08', '\x2E', '\xA1', '\x66', '\x28', '\xD9', '\x24', '\xB2', '\x76', '\x5B', '\xA2', '\x49', '\x6D', '\x8B', '\xD1', '\x25',
	'\x72', '\xF8', '\xF6', '\x64', '\x86', '\x68', '\x98', '\x16', '\xD4', '\xA4', '\x5C', '\xCC', '\x5D', '\x65', '\xB6', '\x92',
	'\x6C', '\x70', '\x48', '\x50', '\xFD', '\xED', '\xB9', '\xDA', '\x5E', '\x15', '\x46', '\x57', '\xA7', '\x8D', '\x9D', '\x84',
	'\x90', '\xD8', '\xAB', '\x00', '\x8C', '\xBC', '\xD3', '\x0A', '\xF7', '\xE4', '\x58', '\x05', '\xB8', '\xB3', '\x45', '\x06',
	'\xD0', '\x2C', '\x1E', '\x8F', '\xCA', '\x3F', '\x0F', '\x02', '\xC1', '\xAF', '\xBD', '\x03', '\x01', '\x13', '\x8A', '\x6B',
	'\x3A', '\x91', '\x11', '\x41', '\x4F', '\x67', '\xDC', '\xEA', '\x97', '\xF2', '\xCF', '\xCE', '\xF0', '\xB4', '\xE6', '\x73',
	'\x96', '\xAC', '\x74', '\x22', '\xE7', '\xAD', '\x35', '\x85', '\xE2', '\xF9', '\x37', '\xE8', '\x1C', '\x75', '\xDF', '\x6E',
	'\x47', '\xF1', '\x1A', '\x71', '\x1D', '\x29', '\xC5', '\x89', '\x6F', '\xB7', '\x62', '\x0E', '\xAA', '\x18', '\xBE', '\x1B',
	'\xFC', '\x56', '\x3E', '\x4B', '\xC6', '\xD2', '\x79', '\x20', '\x9A', '\xDB', '\xC0', '\xFE', '\x78', '\xCD', '\x5A', '\xF4',
	'\x1F', '\xDD', '\xA8', '\x33', '\x88', '\x07', '\xC7', '\x31', '\xB1', '\x12', '\x10', '\x59', '\x27', '\x80', '\xEC', '\x5F',
	'\x60', '\x51', '\x7F', '\xA9', '\x19', '\xB5', '\x4A', '\x0D', '\x2D', '\xE5', '\x7A', '\x9F', '\x93', '\xC9', '\x9C', '\xEF',
	'\xA0', '\xE0', '\x3B', '\x4D', '\xAE', '\x2A', '\xF5', '\xB0', '\xC8', '\xEB', '\xBB', '\x3C', '\x83', '\x53', '\x99', '\x61',
	'\x17', '\x2B', '\x04', '\x7E', '\xBA', '\x77', '\xD6', '\x26', '\xE1', '\x69', '\x14', '\x63', '\x55', '\x21', '\x0C', '\x7D'}

var multi2 = [256]byte{
	'\x00', '\x02', '\x04', '\x06', '\x08', '\x0a', '\x0c', '\x0e', '\x10', '\x12', '\x14', '\x16', '\x18', '\x1a', '\x1c', '\x1e',
	'\x20', '\x22', '\x24', '\x26', '\x28', '\x2a', '\x2c', '\x2e', '\x30', '\x32', '\x34', '\x36', '\x38', '\x3a', '\x3c', '\x3e',
	'\x40', '\x42', '\x44', '\x46', '\x48', '\x4a', '\x4c', '\x4e', '\x50', '\x52', '\x54', '\x56', '\x58', '\x5a', '\x5c', '\x5e',
	'\x60', '\x62', '\x64', '\x66', '\x68', '\x6a', '\x6c', '\x6e', '\x70', '\x72', '\x74', '\x76', '\x78', '\x7a', '\x7c', '\x7e',
	'\x80', '\x82', '\x84', '\x86', '\x88', '\x8a', '\x8c', '\x8e', '\x90', '\x92', '\x94', '\x96', '\x98', '\x9a', '\x9c', '\x9e',
	'\xa0', '\xa2', '\xa4', '\xa6', '\xa8', '\xaa', '\xac', '\xae', '\xb0', '\xb2', '\xb4', '\xb6', '\xb8', '\xba', '\xbc', '\xbe',
	'\xc0', '\xc2', '\xc4', '\xc6', '\xc8', '\xca', '\xcc', '\xce', '\xd0', '\xd2', '\xd4', '\xd6', '\xd8', '\xda', '\xdc', '\xde',
	'\xe0', '\xe2', '\xe4', '\xe6', '\xe8', '\xea', '\xec', '\xee', '\xf0', '\xf2', '\xf4', '\xf6', '\xf8', '\xfa', '\xfc', '\xfe',
	'\x1b', '\x19', '\x1f', '\x1d', '\x13', '\x11', '\x17', '\x15', '\x0b', '\x09', '\x0f', '\x0d', '\x03', '\x01', '\x07', '\x05',
	'\x3b', '\x39', '\x3f', '\x3d', '\x33', '\x31', '\x37', '\x35', '\x2b', '\x29', '\x2f', '\x2d', '\x23', '\x21', '\x27', '\x25',
	'\x5b', '\x59', '\x5f', '\x5d', '\x53', '\x51', '\x57', '\x55', '\x4b', '\x49', '\x4f', '\x4d', '\x43', '\x41', '\x47', '\x45',
	'\x7b', '\x79', '\x7f', '\x7d', '\x73', '\x71', '\x77', '\x75', '\x6b', '\x69', '\x6f', '\x6d', '\x63', '\x61', '\x67', '\x65',
	'\x9b', '\x99', '\x9f', '\x9d', '\x93', '\x91', '\x97', '\x95', '\x8b', '\x89', '\x8f', '\x8d', '\x83', '\x81', '\x87', '\x85',
	'\xbb', '\xb9', '\xbf', '\xbd', '\xb3', '\xb1', '\xb7', '\xb5', '\xab', '\xa9', '\xaf', '\xad', '\xa3', '\xa1', '\xa7', '\xa5',
	'\xdb', '\xd9', '\xdf', '\xdd', '\xd3', '\xd1', '\xd7', '\xd5', '\xcb', '\xc9', '\xcf', '\xcd', '\xc3', '\xc1', '\xc7', '\xc5',
	'\xfb', '\xf9', '\xff', '\xfd', '\xf3', '\xf1', '\xf7', '\xf5', '\xeb', '\xe9', '\xef', '\xed', '\xe3', '\xe1', '\xe7', '\xe5'}

var multi3 = [256]byte{
	'\x00', '\x03', '\x06', '\x05', '\x0c', '\x0f', '\x0a', '\x09', '\x18', '\x1b', '\x1e', '\x1d', '\x14', '\x17', '\x12', '\x11',
	'\x30', '\x33', '\x36', '\x35', '\x3c', '\x3f', '\x3a', '\x39', '\x28', '\x2b', '\x2e', '\x2d', '\x24', '\x27', '\x22', '\x21',
	'\x60', '\x63', '\x66', '\x65', '\x6c', '\x6f', '\x6a', '\x69', '\x78', '\x7b', '\x7e', '\x7d', '\x74', '\x77', '\x72', '\x71',
	'\x50', '\x53', '\x56', '\x55', '\x5c', '\x5f', '\x5a', '\x59', '\x48', '\x4b', '\x4e', '\x4d', '\x44', '\x47', '\x42', '\x41',
	'\xc0', '\xc3', '\xc6', '\xc5', '\xcc', '\xcf', '\xca', '\xc9', '\xd8', '\xdb', '\xde', '\xdd', '\xd4', '\xd7', '\xd2', '\xd1',
	'\xf0', '\xf3', '\xf6', '\xf5', '\xfc', '\xff', '\xfa', '\xf9', '\xe8', '\xeb', '\xee', '\xed', '\xe4', '\xe7', '\xe2', '\xe1',
	'\xa0', '\xa3', '\xa6', '\xa5', '\xac', '\xaf', '\xaa', '\xa9', '\xb8', '\xbb', '\xbe', '\xbd', '\xb4', '\xb7', '\xb2', '\xb1',
	'\x90', '\x93', '\x96', '\x95', '\x9c', '\x9f', '\x9a', '\x99', '\x88', '\x8b', '\x8e', '\x8d', '\x84', '\x87', '\x82', '\x81',
	'\x9b', '\x98', '\x9d', '\x9e', '\x97', '\x94', '\x91', '\x92', '\x83', '\x80', '\x85', '\x86', '\x8f', '\x8c', '\x89', '\x8a',
	'\xab', '\xa8', '\xad', '\xae', '\xa7', '\xa4', '\xa1', '\xa2', '\xb3', '\xb0', '\xb5', '\xb6', '\xbf', '\xbc', '\xb9', '\xba',
	'\xfb', '\xf8', '\xfd', '\xfe', '\xf7', '\xf4', '\xf1', '\xf2', '\xe3', '\xe0', '\xe5', '\xe6', '\xef', '\xec', '\xe9', '\xea',
	'\xcb', '\xc8', '\xcd', '\xce', '\xc7', '\xc4', '\xc1', '\xc2', '\xd3', '\xd0', '\xd5', '\xd6', '\xdf', '\xdc', '\xd9', '\xda',
	'\x5b', '\x58', '\x5d', '\x5e', '\x57', '\x54', '\x51', '\x52', '\x43', '\x40', '\x45', '\x46', '\x4f', '\x4c', '\x49', '\x4a',
	'\x6b', '\x68', '\x6d', '\x6e', '\x67', '\x64', '\x61', '\x62', '\x73', '\x70', '\x75', '\x76', '\x7f', '\x7c', '\x79', '\x7a',
	'\x3b', '\x38', '\x3d', '\x3e', '\x37', '\x34', '\x31', '\x32', '\x23', '\x20', '\x25', '\x26', '\x2f', '\x2c', '\x29', '\x2a',
	'\x0b', '\x08', '\x0d', '\x0e', '\x07', '\x04', '\x01', '\x02', '\x13', '\x10', '\x15', '\x16', '\x1f', '\x1c', '\x19', '\x1a'}

var multi9 = [256]byte{
	'\x00', '\x09', '\x12', '\x1b', '\x24', '\x2d', '\x36', '\x3f', '\x48', '\x41', '\x5a', '\x53', '\x6c', '\x65', '\x7e', '\x77',
	'\x90', '\x99', '\x82', '\x8b', '\xb4', '\xbd', '\xa6', '\xaf', '\xd8', '\xd1', '\xca', '\xc3', '\xfc', '\xf5', '\xee', '\xe7',
	'\x3b', '\x32', '\x29', '\x20', '\x1f', '\x16', '\x0d', '\x04', '\x73', '\x7a', '\x61', '\x68', '\x57', '\x5e', '\x45', '\x4c',
	'\xab', '\xa2', '\xb9', '\xb0', '\x8f', '\x86', '\x9d', '\x94', '\xe3', '\xea', '\xf1', '\xf8', '\xc7', '\xce', '\xd5', '\xdc',
	'\x76', '\x7f', '\x64', '\x6d', '\x52', '\x5b', '\x40', '\x49', '\x3e', '\x37', '\x2c', '\x25', '\x1a', '\x13', '\x08', '\x01',
	'\xe6', '\xef', '\xf4', '\xfd', '\xc2', '\xcb', '\xd0', '\xd9', '\xae', '\xa7', '\xbc', '\xb5', '\x8a', '\x83', '\x98', '\x91',
	'\x4d', '\x44', '\x5f', '\x56', '\x69', '\x60', '\x7b', '\x72', '\x05', '\x0c', '\x17', '\x1e', '\x21', '\x28', '\x33', '\x3a',
	'\xdd', '\xd4', '\xcf', '\xc6', '\xf9', '\xf0', '\xeb', '\xe2', '\x95', '\x9c', '\x87', '\x8e', '\xb1', '\xb8', '\xa3', '\xaa',
	'\xec', '\xe5', '\xfe', '\xf7', '\xc8', '\xc1', '\xda', '\xd3', '\xa4', '\xad', '\xb6', '\xbf', '\x80', '\x89', '\x92', '\x9b',
	'\x7c', '\x75', '\x6e', '\x67', '\x58', '\x51', '\x4a', '\x43', '\x34', '\x3d', '\x26', '\x2f', '\x10', '\x19', '\x02', '\x0b',
	'\xd7', '\xde', '\xc5', '\xcc', '\xf3', '\xfa', '\xe1', '\xe8', '\x9f', '\x96', '\x8d', '\x84', '\xbb', '\xb2', '\xa9', '\xa0',
	'\x47', '\x4e', '\x55', '\x5c', '\x63', '\x6a', '\x71', '\x78', '\x0f', '\x06', '\x1d', '\x14', '\x2b', '\x22', '\x39', '\x30',
	'\x9a', '\x93', '\x88', '\x81', '\xbe', '\xb7', '\xac', '\xa5', '\xd2', '\xdb', '\xc0', '\xc9', '\xf6', '\xff', '\xe4', '\xed',
	'\x0a', '\x03', '\x18', '\x11', '\x2e', '\x27', '\x3c', '\x35', '\x42', '\x4b', '\x50', '\x59', '\x66', '\x6f', '\x74', '\x7d',
	'\xa1', '\xa8', '\xb3', '\xba', '\x85', '\x8c', '\x97', '\x9e', '\xe9', '\xe0', '\xfb', '\xf2', '\xcd', '\xc4', '\xdf', '\xd6',
	'\x31', '\x38', '\x23', '\x2a', '\x15', '\x1c', '\x07', '\x0e', '\x79', '\x70', '\x6b', '\x62', '\x5d', '\x54', '\x4f', '\x46'}

var multi11 = [256]byte{
	'\x00', '\x0b', '\x16', '\x1d', '\x2c', '\x27', '\x3a', '\x31', '\x58', '\x53', '\x4e', '\x45', '\x74', '\x7f', '\x62', '\x69',
	'\xb0', '\xbb', '\xa6', '\xad', '\x9c', '\x97', '\x8a', '\x81', '\xe8', '\xe3', '\xfe', '\xf5', '\xc4', '\xcf', '\xd2', '\xd9',
	'\x7b', '\x70', '\x6d', '\x66', '\x57', '\x5c', '\x41', '\x4a', '\x23', '\x28', '\x35', '\x3e', '\x0f', '\x04', '\x19', '\x12',
	'\xcb', '\xc0', '\xdd', '\xd6', '\xe7', '\xec', '\xf1', '\xfa', '\x93', '\x98', '\x85', '\x8e', '\xbf', '\xb4', '\xa9', '\xa2',
	'\xf6', '\xfd', '\xe0', '\xeb', '\xda', '\xd1', '\xcc', '\xc7', '\xae', '\xa5', '\xb8', '\xb3', '\x82', '\x89', '\x94', '\x9f',
	'\x46', '\x4d', '\x50', '\x5b', '\x6a', '\x61', '\x7c', '\x77', '\x1e', '\x15', '\x08', '\x03', '\x32', '\x39', '\x24', '\x2f',
	'\x8d', '\x86', '\x9b', '\x90', '\xa1', '\xaa', '\xb7', '\xbc', '\xd5', '\xde', '\xc3', '\xc8', '\xf9', '\xf2', '\xef', '\xe4',
	'\x3d', '\x36', '\x2b', '\x20', '\x11', '\x1a', '\x07', '\x0c', '\x65', '\x6e', '\x73', '\x78', '\x49', '\x42', '\x5f', '\x54',
	'\xf7', '\xfc', '\xe1', '\xea', '\xdb', '\xd0', '\xcd', '\xc6', '\xaf', '\xa4', '\xb9', '\xb2', '\x83', '\x88', '\x95', '\x9e',
	'\x47', '\x4c', '\x51', '\x5a', '\x6b', '\x60', '\x7d', '\x76', '\x1f', '\x14', '\x09', '\x02', '\x33', '\x38', '\x25', '\x2e',
	'\x8c', '\x87', '\x9a', '\x91', '\xa0', '\xab', '\xb6', '\xbd', '\xd4', '\xdf', '\xc2', '\xc9', '\xf8', '\xf3', '\xee', '\xe5',
	'\x3c', '\x37', '\x2a', '\x21', '\x10', '\x1b', '\x06', '\x0d', '\x64', '\x6f', '\x72', '\x79', '\x48', '\x43', '\x5e', '\x55',
	'\x01', '\x0a', '\x17', '\x1c', '\x2d', '\x26', '\x3b', '\x30', '\x59', '\x52', '\x4f', '\x44', '\x75', '\x7e', '\x63', '\x68',
	'\xb1', '\xba', '\xa7', '\xac', '\x9d', '\x96', '\x8b', '\x80', '\xe9', '\xe2', '\xff', '\xf4', '\xc5', '\xce', '\xd3', '\xd8',
	'\x7a', '\x71', '\x6c', '\x67', '\x56', '\x5d', '\x40', '\x4b', '\x22', '\x29', '\x34', '\x3f', '\x0e', '\x05', '\x18', '\x13',
	'\xca', '\xc1', '\xdc', '\xd7', '\xe6', '\xed', '\xf0', '\xfb', '\x92', '\x99', '\x84', '\x8f', '\xbe', '\xb5', '\xa8', '\xa3'}

var multi13 = [256]byte{
	'\x00', '\x0d', '\x1a', '\x17', '\x34', '\x39', '\x2e', '\x23', '\x68', '\x65', '\x72', '\x7f', '\x5c', '\x51', '\x46', '\x4b',
	'\xd0', '\xdd', '\xca', '\xc7', '\xe4', '\xe9', '\xfe', '\xf3', '\xb8', '\xb5', '\xa2', '\xaf', '\x8c', '\x81', '\x96', '\x9b',
	'\xbb', '\xb6', '\xa1', '\xac', '\x8f', '\x82', '\x95', '\x98', '\xd3', '\xde', '\xc9', '\xc4', '\xe7', '\xea', '\xfd', '\xf0',
	'\x6b', '\x66', '\x71', '\x7c', '\x5f', '\x52', '\x45', '\x48', '\x03', '\x0e', '\x19', '\x14', '\x37', '\x3a', '\x2d', '\x20',
	'\x6d', '\x60', '\x77', '\x7a', '\x59', '\x54', '\x43', '\x4e', '\x05', '\x08', '\x1f', '\x12', '\x31', '\x3c', '\x2b', '\x26',
	'\xbd', '\xb0', '\xa7', '\xaa', '\x89', '\x84', '\x93', '\x9e', '\xd5', '\xd8', '\xcf', '\xc2', '\xe1', '\xec', '\xfb', '\xf6',
	'\xd6', '\xdb', '\xcc', '\xc1', '\xe2', '\xef', '\xf8', '\xf5', '\xbe', '\xb3', '\xa4', '\xa9', '\x8a', '\x87', '\x90', '\x9d',
	'\x06', '\x0b', '\x1c', '\x11', '\x32', '\x3f', '\x28', '\x25', '\x6e', '\x63', '\x74', '\x79', '\x5a', '\x57', '\x40', '\x4d',
	'\xda', '\xd7', '\xc0', '\xcd', '\xee', '\xe3', '\xf4', '\xf9', '\xb2', '\xbf', '\xa8', '\xa5', '\x86', '\x8b', '\x9c', '\x91',
	'\x0a', '\x07', '\x10', '\x1d', '\x3e', '\x33', '\x24', '\x29', '\x62', '\x6f', '\x78', '\x75', '\x56', '\x5b', '\x4c', '\x41',
	'\x61', '\x6c', '\x7b', '\x76', '\x55', '\x58', '\x4f', '\x42', '\x09', '\x04', '\x13', '\x1e', '\x3d', '\x30', '\x27', '\x2a',
	'\xb1', '\xbc', '\xab', '\xa6', '\x85', '\x88', '\x9f', '\x92', '\xd9', '\xd4', '\xc3', '\xce', '\xed', '\xe0', '\xf7', '\xfa',
	'\xb7', '\xba', '\xad', '\xa0', '\x83', '\x8e', '\x99', '\x94', '\xdf', '\xd2', '\xc5', '\xc8', '\xeb', '\xe6', '\xf1', '\xfc',
	'\x67', '\x6a', '\x7d', '\x70', '\x53', '\x5e', '\x49', '\x44', '\x0f', '\x02', '\x15', '\x18', '\x3b', '\x36', '\x21', '\x2c',
	'\x0c', '\x01', '\x16', '\x1b', '\x38', '\x35', '\x22', '\x2f', '\x64', '\x69', '\x7e', '\x73', '\x50', '\x5d', '\x4a', '\x47',
	'\xdc', '\xd1', '\xc6', '\xcb', '\xe8', '\xe5', '\xf2', '\xff', '\xb4', '\xb9', '\xae', '\xa3', '\x80', '\x8d', '\x9a', '\x97'}

var multi14 = [256]byte{
	'\x00', '\x0e', '\x1c', '\x12', '\x38', '\x36', '\x24', '\x2a', '\x70', '\x7e', '\x6c', '\x62', '\x48', '\x46', '\x54', '\x5a',
	'\xe0', '\xee', '\xfc', '\xf2', '\xd8', '\xd6', '\xc4', '\xca', '\x90', '\x9e', '\x8c', '\x82', '\xa8', '\xa6', '\xb4', '\xba',
	'\xdb', '\xd5', '\xc7', '\xc9', '\xe3', '\xed', '\xff', '\xf1', '\xab', '\xa5', '\xb7', '\xb9', '\x93', '\x9d', '\x8f', '\x81',
	'\x3b', '\x35', '\x27', '\x29', '\x03', '\x0d', '\x1f', '\x11', '\x4b', '\x45', '\x57', '\x59', '\x73', '\x7d', '\x6f', '\x61',
	'\xad', '\xa3', '\xb1', '\xbf', '\x95', '\x9b', '\x89', '\x87', '\xdd', '\xd3', '\xc1', '\xcf', '\xe5', '\xeb', '\xf9', '\xf7',
	'\x4d', '\x43', '\x51', '\x5f', '\x75', '\x7b', '\x69', '\x67', '\x3d', '\x33', '\x21', '\x2f', '\x05', '\x0b', '\x19', '\x17',
	'\x76', '\x78', '\x6a', '\x64', '\x4e', '\x40', '\x52', '\x5c', '\x06', '\x08', '\x1a', '\x14', '\x3e', '\x30', '\x22', '\x2c',
	'\x96', '\x98', '\x8a', '\x84', '\xae', '\xa0', '\xb2', '\xbc', '\xe6', '\xe8', '\xfa', '\xf4', '\xde', '\xd0', '\xc2', '\xcc',
	'\x41', '\x4f', '\x5d', '\x53', '\x79', '\x77', '\x65', '\x6b', '\x31', '\x3f', '\x2d', '\x23', '\x09', '\x07', '\x15', '\x1b',
	'\xa1', '\xaf', '\xbd', '\xb3', '\x99', '\x97', '\x85', '\x8b', '\xd1', '\xdf', '\xcd', '\xc3', '\xe9', '\xe7', '\xf5', '\xfb',
	'\x9a', '\x94', '\x86', '\x88', '\xa2', '\xac', '\xbe', '\xb0', '\xea', '\xe4', '\xf6', '\xf8', '\xd2', '\xdc', '\xce', '\xc0',
	'\x7a', '\x74', '\x66', '\x68', '\x42', '\x4c', '\x5e', '\x50', '\x0a', '\x04', '\x16', '\x18', '\x32', '\x3c', '\x2e', '\x20',
	'\xec', '\xe2', '\xf0', '\xfe', '\xd4', '\xda', '\xc8', '\xc6', '\x9c', '\x92', '\x80', '\x8e', '\xa4', '\xaa', '\xb8', '\xb6',
	'\x0c', '\x02', '\x10', '\x1e', '\x34', '\x3a', '\x28', '\x26', '\x7c', '\x72', '\x60', '\x6e', '\x44', '\x4a', '\x58', '\x56',
	'\x37', '\x39', '\x2b', '\x25', '\x0f', '\x01', '\x13', '\x1d', '\x47', '\x49', '\x5b', '\x55', '\x7f', '\x71', '\x63', '\x6d',
	'\xd7', '\xd9', '\xcb', '\xc5', '\xef', '\xe1', '\xf3', '\xfd', '\xa7', '\xa9', '\xbb', '\xb5', '\x9f', '\x91', '\x83', '\x8d'}

var rcon = [256]byte{
	'\x8d', '\x01', '\x02', '\x04', '\x08', '\x10', '\x20', '\x40', '\x80', '\x1b', '\x36', '\x6c', '\xd8', '\xab', '\x4d', '\x9a',
	'\x2f', '\x5e', '\xbc', '\x63', '\xc6', '\x97', '\x35', '\x6a', '\xd4', '\xb3', '\x7d', '\xfa', '\xef', '\xc5', '\x91', '\x39',
	'\x72', '\xe4', '\xd3', '\xbd', '\x61', '\xc2', '\x9f', '\x25', '\x4a', '\x94', '\x33', '\x66', '\xcc', '\x83', '\x1d', '\x3a',
	'\x74', '\xe8', '\xcb', '\x8d', '\x01', '\x02', '\x04', '\x08', '\x10', '\x20', '\x40', '\x80', '\x1b', '\x36', '\x6c', '\xd8',
	'\xab', '\x4d', '\x9a', '\x2f', '\x5e', '\xbc', '\x63', '\xc6', '\x97', '\x35', '\x6a', '\xd4', '\xb3', '\x7d', '\xfa', '\xef',
	'\xc5', '\x91', '\x39', '\x72', '\xe4', '\xd3', '\xbd', '\x61', '\xc2', '\x9f', '\x25', '\x4a', '\x94', '\x33', '\x66', '\xcc',
	'\x83', '\x1d', '\x3a', '\x74', '\xe8', '\xcb', '\x8d', '\x01', '\x02', '\x04', '\x08', '\x10', '\x20', '\x40', '\x80', '\x1b',
	'\x36', '\x6c', '\xd8', '\xab', '\x4d', '\x9a', '\x2f', '\x5e', '\xbc', '\x63', '\xc6', '\x97', '\x35', '\x6a', '\xd4', '\xb3',
	'\x7d', '\xfa', '\xef', '\xc5', '\x91', '\x39', '\x72', '\xe4', '\xd3', '\xbd', '\x61', '\xc2', '\x9f', '\x25', '\x4a', '\x94',
	'\x33', '\x66', '\xcc', '\x83', '\x1d', '\x3a', '\x74', '\xe8', '\xcb', '\x8d', '\x01', '\x02', '\x04', '\x08', '\x10', '\x20',
	'\x40', '\x80', '\x1b', '\x36', '\x6c', '\xd8', '\xab', '\x4d', '\x9a', '\x2f', '\x5e', '\xbc', '\x63', '\xc6', '\x97', '\x35',
	'\x6a', '\xd4', '\xb3', '\x7d', '\xfa', '\xef', '\xc5', '\x91', '\x39', '\x72', '\xe4', '\xd3', '\xbd', '\x61', '\xc2', '\x9f',
	'\x25', '\x4a', '\x94', '\x33', '\x66', '\xcc', '\x83', '\x1d', '\x3a', '\x74', '\xe8', '\xcb', '\x8d', '\x01', '\x02', '\x04',
	'\x08', '\x10', '\x20', '\x40', '\x80', '\x1b', '\x36', '\x6c', '\xd8', '\xab', '\x4d', '\x9a', '\x2f', '\x5e', '\xbc', '\x63',
	'\xc6', '\x97', '\x35', '\x6a', '\xd4', '\xb3', '\x7d', '\xfa', '\xef', '\xc5', '\x91', '\x39', '\x72', '\xe4', '\xd3', '\xbd',
	'\x61', '\xc2', '\x9f', '\x25', '\x4a', '\x94', '\x33', '\x66', '\xcc', '\x83', '\x1d', '\x3a', '\x74', '\xe8', '\xcb', '\x8d'}

// State this is a 4 by 4 AES 32-byte 2D array.
type State [4][4]byte

// SubBytes funciton for AES
func SubBytes(state State) State {
	var statePrime State
	for row := 0; row < 4; row++ {
		for col := 0; col < 4; col++ {
			statePrime[row][col] = sbox[state[row][col]]
		}
	}
	return statePrime
}

// InvSubBytes funciton for AES
func InvSubBytes(state State) State {
	var statePrime State
	for row := 0; row < 4; row++ {
		for col := 0; col < 4; col++ {
			statePrime[row][col] = invSbox[state[row][col]]
		}
	}
	return statePrime
}

// ShiftRows function for AES
func ShiftRows(state State) State {
	var statePrime State
	for row := 0; row < 4; row++ {
		for col := 0; col < 4; col++ {
			if row == 0 {
				statePrime[row][col] = state[row][col]
			} else {
				shiftCol := (col + row) % 4
				statePrime[row][col] = state[row][shiftCol]
			}
		}
	}
	return statePrime
}

func InvShiftRows(state State) State {
	var statePrime State
	for row := 0; row < 4; row++ {
		for col := 0; col < 4; col++ {
			if row == 0 {
				statePrime[row][col] = state[row][col]
			} else {
				shiftCol := (col + 4 - row) % 4
				statePrime[row][col] = state[row][shiftCol]
			}
		}
	}
	return statePrime
}

// MixColumns function for AES
func MixColumns(state State) State {
	var statePrime State
	for col := 0; col < 4; col++ {
		statePrime[0][col] = multi2[state[0][col]] ^ multi3[state[1][col]] ^ state[2][col] ^ state[3][col]
		statePrime[1][col] = state[0][col] ^ multi2[state[1][col]] ^ multi3[state[2][col]] ^ state[3][col]
		statePrime[2][col] = state[0][col] ^ state[1][col] ^ multi2[state[2][col]] ^ multi3[state[3][col]]
		statePrime[3][col] = multi3[state[0][col]] ^ state[1][col] ^ state[2][col] ^ multi2[state[3][col]]
	}
	return statePrime
}

// MixColumns function for AES
func InvMixColumns(state State) State {
	var statePrime State
	for col := 0; col < 4; col++ {
		statePrime[0][col] = multi14[state[0][col]] ^ multi11[state[1][col]] ^ multi13[state[2][col]] ^ multi9[state[3][col]]
		statePrime[1][col] = multi9[state[0][col]] ^ multi14[state[1][col]] ^ multi11[state[2][col]] ^ multi13[state[3][col]]
		statePrime[2][col] = multi13[state[0][col]] ^ multi9[state[1][col]] ^ multi14[state[2][col]] ^ multi11[state[3][col]]
		statePrime[3][col] = multi11[state[0][col]] ^ multi13[state[1][col]] ^ multi9[state[2][col]] ^ multi14[state[3][col]]
	}
	return statePrime
}

// SubWord function for the Key Schedule Expansion
func SubWord(fourByteWord []byte) []byte {
	var result []byte
	result = append(result, sbox[fourByteWord[0]])
	result = append(result, sbox[fourByteWord[1]])
	result = append(result, sbox[fourByteWord[2]])
	result = append(result, sbox[fourByteWord[3]])
	return result
}

// RotWord function for the Key Schedule Expansion
func RotWord(fourByteWord []byte) []byte {
	var result []byte
	result = append(result, fourByteWord[1])
	result = append(result, fourByteWord[2])
	result = append(result, fourByteWord[3])
	result = append(result, fourByteWord[0])
	return result
}

// Rcon function for the Key Schedule Expansion
func Rcon(i int) []byte {
	return []byte{rcon[i], '\x00', '\x00', '\x00'}
}

// KeyExpansion function for the Key Schedule Expansion
func KeyExpansion(key []byte, aesNk int, aesNr int) []byte {
	var w = make([]byte, aesBlockSize*(aesNr+1)*4)
	var temp = make([]byte, 4)

	for i := 0; i < aesNk; i++ {
		copy(w[i*4:i*4+4], key[4*i:4*i+4])
	}

	for i := aesNk; i < aesBlockSize*(aesNr+1); i++ {
		word := i - 1
		start := word * 4
		end := word*4 + 4
		copy(temp[0:4], w[start:end])
		if i%aesNk == 0 {
			temp = utils.XOR(SubWord(RotWord(temp)), Rcon(i/aesNk))
		} else if aesNk > 6 && i%aesNk == 4 {
			temp = SubWord(temp)
		}
		copy(w[i*4:i*4+4], utils.XOR(w[4*(i-aesNk):4*(i-aesNk)+4], temp))
	}
	return w
}

// AddRouncKey function from 5.1.4
func AddRoundKey(state State, keyScheduleSection []byte) State {
	var statePrime State
	keyScheduleAsState := arrayToState(keyScheduleSection)
	for col := 0; col < 4; col++ {
		for row := 0; row < 4; row++ {
			statePrime[row][col] = state[row][col] ^ keyScheduleAsState[row][col]
		}
	}
	return statePrime
}

func prettyPrintState(state State) {
	fmt.Println("\n")
	for i := 0; i < 4; i++ {
		row := state[i]
		fmt.Printf("%v\n", utils.BytesToHexString(row[0:4]))
	}
	fmt.Println("\n")
}

func arrayToState(a []byte) State {
	var state State
	for row := 0; row < 4; row++ {
		for col := 0; col < 4; col++ {
			state[row][col] = a[row+col*4]
		}
	}
	return state
}

func stateToArray(state State) []byte {
	var a []byte
	for col := 0; col < 4; col++ {
		for row := 0; row < 4; row++ {
			a = append(a, state[row][col])
		}
	}
	return a
}

func Aes128Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	if len(plaintext) != 16 {
		return nil, errors.New("Plaintext must be 16 bytes")
	}

	var state State = arrayToState(plaintext)

	keySchedule := KeyExpansion(key, aes128KeySize, aes128Rounds)

	state = AddRoundKey(state, keySchedule[0:4*4])

	for round := 1; round <= aes128Rounds-1; round++ {
		state = SubBytes(state)
		state = ShiftRows(state)
		state = MixColumns(state)
		state = AddRoundKey(state, keySchedule[round*4*4:(round*4*4)+4*4])
	}

	state = SubBytes(state)

	state = ShiftRows(state)

	state = AddRoundKey(state, keySchedule[aes128Rounds*4*4:(aes128Rounds*4*4)+4*4])

	return stateToArray(state), nil
}

func Aes128Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	if len(ciphertext) != 16 {
		return nil, errors.New("Ciphertext must be 16 bytes")
	}

	var state State = arrayToState(ciphertext)

	keySchedule := KeyExpansion(key, aes128KeySize, aes128Rounds)

	state = AddRoundKey(state, keySchedule[aes128Rounds*4*4:(aes128Rounds*4*4)+4*4])

	for round := aes128Rounds - 1; round >= 1; round-- {
		state = InvShiftRows(state)
		state = InvSubBytes(state)
		state = AddRoundKey(state, keySchedule[round*4*4:(round*4*4)+4*4])
		state = InvMixColumns(state)
	}

	state = InvSubBytes(state)

	state = InvShiftRows(state)

	state = AddRoundKey(state, keySchedule[0:4*4])

	return stateToArray(state), nil
}

func testAes128() {
	var input = []byte{
		'\x00', '\x11', '\x22', '\x33', '\x44', '\x55', '\x66', '\x77',
		'\x88', '\x99', '\xaa', '\xbb', '\xcc', '\xdd', '\xee', '\xff'}

	var key = []byte{
		'\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07',
		'\x08', '\x09', '\x0a', '\x0b', '\x0c', '\x0d', '\x0e', '\x0f'}

	// test encryption
	ciphertext, err := Aes128Encrypt(input, key)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(utils.BytesToHexString(ciphertext))

	// test decryption
	plaintext, err := Aes128Decrypt(ciphertext, key)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(utils.BytesToHexString(plaintext))
}

func main() {
	key := []byte("YELLOW SUBMARINE")
	buf := utils.Base64ToBytes(cipherFileName)
	for i := 0; i < len(buf)/16; i++ {
		plaintext, err := Aes128Decrypt(buf[i*16:i*16+16], key)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf(string(plaintext))
	}
}
