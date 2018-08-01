# Secret Messages
# Objective: Using Ceasar Cipher encrypt your messages
# Casey Salvador
# 8/1/2018

alphabet = 'abcdefghijklmnopqrstuvwxyz'
key = 5
newMessage = ''

# test by printing a letter in alphabet
# print(alphabet[5])

decision = input('Please enter E (encrypt) or D (decrypt): ')
if decision == 'E':
    # prompt user for message
    message = input('Please enter a message to encrypt: ')

    # Encrypt a message
    for character in message:
        if character in alphabet:
            # find the position of the character
            position = alphabet.find(character)
            #print('This is the position: ', position)

            # encrypt the character
            newPosition = (position + key) % 26 #this allows to set position back to 0 using modulus because there isn't 27 letters in the alphabet.
            #print('This is the new position: ', newPosition)

            # print letter at the new position
            newCharacter = alphabet[newPosition]
            #print('This is the old character: ', character, 'new character: ', newCharacter)
            newMessage += newCharacter
        else:
            newMessage += character
    print('New Message: ', newMessage)

else:
    # prompt user for message to decrypt
    decryptMessage = input('Please enter message to decrypt: ')

    # Decrypt a message
    for char in decryptMessage:
        if char in alphabet:
            position = alphabet.find(char)
            newPosition = (position - key) % 26
            newChar = alphabet[newPosition]
            newMessage += newChar
        else:
            newMessage += char
    print('Decrypted Message: ', newMessage)