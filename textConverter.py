

with open('plain_cipherText.txt') as f:
    buf = f.readline()
    lines = f.readlines()
    newF = open('bits.txt', 'w')
    newF.write('PLAIN : CIPHER\n')
    for l in lines:
        hexStrings = l.split(':')
        bitsPlain = f'{int(hexStrings[0],16):0>{16}b}'
        bitsCipher = f'{int(hexStrings[1],16):0>{16}b}'
        newF.write(bitsPlain + ':' + bitsCipher + '\n')