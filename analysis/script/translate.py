import argparse
from enum import Enum
from functools import reduce

class TranslationStatus(Enum):
    NOT_TRANSLATING = -1
    TRANSLATING = 0
    TRANSLATING_STRUCT = 1
    TRANSLATING_FUNC_START = 2
    TRANSLATING_FUNC_BODY_WITH_ANNOTATION = 3
    TRANSLATING_FUNC_BODY_WITHOUT_ANNOTATION = 4

class AnnotationInfo:
    def __init__(self, del_assign, ignore_args, more_out_args, more_in_args):
        self.del_assign = del_assign
        self.ignore_args = ignore_args
        self.more_out_args = more_out_args
        self.more_in_args = more_in_args

class Translator:
    def __init__(self):
        self.write_constants = {
            'endline' : '\n',
            'whitespace': ' ',
            'tab': '  '
        }

        self.ignore_line_starts = [
            '//', '/*', '*', '*/',  # ignore comment lines
            '#include',             # ignore library include lines
            '#define',              # ignore constant definition
            'printf',               # ignore printf & sprintf statement
            'snprintf',
            'EMSG',
            'DMSG',

            # ignore TEE API func. not supported
            'TEE_Free(',            # so to not confuse with TEE_FreeTransient
            'TEE_GetSystemTime',
            'TEE_TIME_SUB'
        ]

        self.need_to_strip_chars = [
            '*', '&' # pointer currently not supported
            
        ]

        self.need_to_strip_type_conversions = [ # type conversion currently not supported
            ' (aes_cipher *)',
            ' (void *)',
            ' (password_handle_t *)',
        ]

        self.var_types = [
            'uint8_t',
            'uint32_t',             # C native
            'uint64_t',
            'size_t',
            'void',
            'char',
            'int ',
            'bool',

            'TEE_OperationHandle',  # TEE types
            'TEE_ObjectHandle',
            'TEE_Result',
            'TEE_Attribute',

            # custom types (kmgk)
            'secure_id_t',
            'salt_t',
            'password_handle_t'
        ]

        self.struct_types = [       # TODO: accumulate struct types as translating
            'TEE_ObjectInfo',       # currently manually added
            'aes_cipher',
            'password_handle_t',
            'hw_auth_token_t'
        ]

        self.translate_mapping = {
            #TODO: need to update
            'payload_reencryption (*session, param_types, TEE_Param params[4])'
            : 'payload_reencryption (*session, ori_cli_id, ori_cli_iv, ori_cli_data, dest_cli_id, dest_cli_data)',
            '(char *) TEE_Malloc(sizeof *dest_cli_iv * (TA_AES_IV_SIZE + 1), 0);' : '# dummyIv;',
            '(char *) TEE_Malloc(sizeof *ori_cli_key * (TA_AES_KEY_SIZE + 1), 0);' : '# randomAttrVal;',
            '(char *) TEE_Malloc(sizeof *dest_cli_key * (TA_AES_KEY_SIZE + 1), 0);' : '# randomAttrVal;',
            '(char *) TEE_Malloc(sizeof *dec_data * dec_data_size, 0);' : '# noData;',
            'TA_Enroll (TEE_Param params[TEE_NUM_PARAMS])'
            : 'TA_Enroll (uid, desired_password, current_password, current_password_handle, error, password_handle)',
            'TA_Verify (TEE_Param params[TEE_NUM_PARAMS])'
            : 'TA_Verify (uid, challenge, enrolled_password_handle, provided_password, response_auth_token)',

            # C syntax to IMP syntax
            '->' : ' . ', 
            ' = ' : ' := ',
            ' == ' : ' === ',
            
            ' 0' : ' # 0',
            ' 1' : ' # 1',
            ' true'  : ' # true',
            ' false' : ' # false',

            # TEE constant translate
            'TEE_TIMEOUT_INFINITE' : '# TEE-TIMEOUT-INFINITE',

            'TEE_STORAGE_PRIVATE' : '# TEE-STORAGE-PRIVATE',

            'TEE_HANDLE_NULL' : '# TEE-HANDLE-NULL',

            'TEE_DATA_FLAG_ACCESS_READ,'         : '# TEE-DATA-FLAG-ACCESS-READ,',
            # 'TEE_DATA_FLAG_SHARE_READ'          : '# TEE-DATA-FLAG-SHARE-READ',
            'TEE_DATA_FLAG_ACCESS_WRITE,'        : '# TEE-DATA-FLAG-ACCESS-WRITE,',
            # 'TEE_DATA_FLAG_ACCESS_WRITE_META'   : '# TEE-DATA-FLAG-ACCESS-WRITE-META',
            # 'TEE_DATA_FLAG_OVERWRITE'           : '# TEE-DATA-FLAG-SHARE-WRITE',
            'TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ'
            : '# (TEE-DATA-FLAG-ACCESS-READ, TEE-DATA-FLAG-SHARE-READ)',
            'TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE'
            : '# (TEE-DATA-FLAG-ACCESS-READ, TEE-DATA-FLAG-ACCESS-WRITE, TEE-DATA-FLAG-ACCESS-WRITE-META, TEE-DATA-FLAG-OVERWRITE)',


            'TEE_TYPE_AES'                      : '# TEE-TYPE-AES',
            'TEE_TYPE_HMAC_SHA256'              : '# TEE-TYPE-SHA256',

            'TEE_ObjectInfo'    : 'TeeObjectInfo',
            'aes_cipher'        : 'AesCipher',
            'password_handle_t' : 'PasswordHandleT',
            'hw_auth_token_t'   : 'HwAuthTokenT',

            'TEE_ATTR_SECRET_VALUE' : '# TEE-ATTR-SECRET-VALUE',

            'TEE_ALG_AES_CBC_NOPAD' : '# TEE-ALG-AES-CBC-NOPAD',
            'TEE_ALG_HMAC_SHA256'   : '# TEE-ALG-HMAC-SHA256',

            'TEE_MODE_ENCRYPT' : '# TEE-MODE-ENCRYPT',
            'TEE_MODE_DECRYPT' : '# TEE-MODE-DECRYPT',
            'TEE_MODE_MAC'     : '# TEE-MODE-MAC',

            'TEE_ERROR_BAD_PARAMETER'   : '# TEE-ERROR-BAD-PARAMETER',
            'TEE_ERROR_GENERIC'         : '# TEE-ERROR-GENERIC',
            'TEE_ERROR_OUT_OF_MEMORY'   : '# TEE-ERROR-OUT-OF-MEMORY',
            'TEE_ERROR_SHORT_BUFFER'    : '# TEE-ERROR-SHORT-BUFFER',
            'TEE_ERROR_BAD_STATE'       : '# TEE-ERROR-BAD-STATE',
            'TEE_ERROR_NOT_SUPPORTED'   : '# TEE-ERROR-NOT-SUPPORTED',
            'TEE_ERROR_ITEM_NOT_FOUND'  : '# TEE-ERROR-ITEM-NOT-FOUND',
            'TEE_ERROR_CORRUPT_OBJECT'  : '# TEE-ERROR-CORRUPT-OBJECT',

            'TEE_SUCCESS' : '# TEE-SUCCESS',

            # TEE API func call translate
            'TEE_GetObjectInfo1'                    : 'GetObjectInfo1',
            'TEE_CloseObject'                       : 'CloseObject',

            'TEE_AllocateTransientObject'           : 'AllocateTransientObject',
            'TEE_InitRefAttribute'                  : 'InitRefAttribute',
            'TEE_FreeTransientObject'               : 'FreeTransientObject',
            'TEE_ResetTransientObject'              : 'ResetTransientObject',
            'TEE_PopulateTransientObject'           : 'PopulateTransientObject',

            'TEE_OpenPersistentObject'              : 'OpenPersistentObject',
            'TEE_CreatePersistentObject'            : 'CreatePersistentObject',
            'TEE_CloseAndDeletePersistentObject1'   : 'CloseAndDeletePersistentObject1',

            'TEE_ReadObjectData'                    : 'ReadObjectData',
            'TEE_WriteObjectData'                   : 'WriteObjectData',

            'TEE_AllocateOperation'                 : 'AllocateOperation',
            'TEE_FreeOperation'                     : 'FreeOperation',
            'TEE_ResetOperation'                    : 'ResetOperation',
            'TEE_SetOperationKey'                   : 'SetOperationKey',

            'TEE_CipherInit'                        : 'CipherInit',
            'TEE_CipherUpdate'                      : 'CipherUpdate',

            'TEE_MACInit'                           : 'MACInit',
            'TEE_MACComputeFinal'                   : 'MACComputeFinal',

            'TEE_GenerateRandom'                    : 'GenerateRandom',

            'TEE_OpenTASession'                     : 'OpenTASession',

            # Custom constants translate (mqttz)
            'TA_AES_KEY_SIZE'                       : '# TA-AES-KEY-SIZE',
            'TA_AES_MODE_ENCODE'                    : '# TA-AES-MODE-ENCODE',
            'TA_AES_MODE_DECODE'                    : '# TA-AES-MODE-DECODE',
            'TA_REENCRYPT'                          : '# TA-REENCRYPT',

            # Custom constants translate (kmgk)
            'HMAC_SHA256_KEY_SIZE_BYTE'             : '# HMAC-SHA256-KEY-SIZE-BYTE',
            'HMAC_SHA256_KEY_SIZE_BIT'              : '# HMAC-SHA256-KEY-SIZE-BIT',
            'TA_KEYMASTER_UUID'                     : '# TA-KEYMASTER-UUID',
            'KM_GET_AUTHTOKEN_KEY'                  : '# KM-GET-AUTHTOKEN-KEY',
            'HW_AUTH_TOKEN_VERSION'                 : '# HW-AUTH-TOKEN-VERSION',
            'ERROR_NONE'                            : '# ERROR-NONE',
            'ERROR_INVALID'                         : '# ERROR-INVALID',
            'ERROR_UNKNOWN'                         : '# ERROR-UNKNOWN',
            'ERROR_RETRY'                           : '# ERROR-RETRY',
            'HANDLE_VERSION'                        : '# HANDLE-VERSION',
            'TEE_TRUE'                              : '# TEE-TRUE',
            'TEE_FALSE'                             : '# TEE-FALSE',
            'GK_ENROLL'                             : '# GK-ENROLL',
            'GK_VERIFY'                             : '# GK-VERIFY',
            'KM_GET_AUTHTOKEN_KEY'                  : '# KM-GET-AUTHTOKEN-KEY'
        }

        self.prev_translation_status = None
        self.translation_status = None
        self.current_annotation_info = None

    def no_need_to_translate(self, line):
        tokens = line.split()
        if len(tokens) == 0: return False # an empty line
        else: 
            for ignore_line_start in self.ignore_line_starts:
                if ignore_line_start in tokens[0]: return True
            return False

    def replace_with_imp_names(self, line, first_capital=False): # key_size -> keySize
        for need_to_strip_char in self.need_to_strip_chars:
            line = line.replace(need_to_strip_char, '')
        while True:
            replace_location = line.rfind('_')
            if replace_location == -1: break 
            else: line = line.replace(line[replace_location:replace_location + 2], line[replace_location + 1].upper())
        return line

    def add_semi_colon(self, line):
        if '; //@noSemiColon' in line: return line.replace('; //@noSemiColon', '')
        elif '//@noSemiColon' in line: return line.replace('//@noSemiColon', '')
        else:
            if ';' in line: return line.replace(';', ' ;')
            else: return line

    def translate_to_imp(self, line):
        for (ori, new) in self.translate_mapping.items(): line = line.replace(ori, new)
        line = self.replace_with_imp_names(line)
        return self.add_semi_colon(line)

    def process_preprocess_line(self, line):
        def is_preprocess_line(line): return ('//@' in line)

        def start_ignore(line): return ('//@ignore' in line)    
        def end_ignore(line): return ('//@endignore' in line)

        def start_process_struct(line): return ('//@process_struct' in line)
        def end_process_struct(line): return ('//@endprocess_struct' in line)

        def start_process_func(line): return ('//@process_func' in line)
        def func_start(line): return '//@func_start' in line

        if not is_preprocess_line(line): return False # normal C line
        else: # is preprocess line
            if start_ignore(line): 
                self.prev_translation_status = self.translation_status
                self.translation_status = TranslationStatus.NOT_TRANSLATING
            elif end_ignore(line): self.translation_status = self.prev_translation_status
            elif start_process_struct(line): self.translation_status = TranslationStatus.TRANSLATING_STRUCT
            elif end_process_struct(line): self.translation_status = TranslationStatus.TRANSLATING
            elif start_process_func(line) or func_start(line): self.translation_status = TranslationStatus.TRANSLATING_FUNC_START
            else: pass
            return True

    def process_func_annotation_line(self, line):
        ignore_args, more_out_args, more_in_args = [], [], []
        tokens = line.split('|')
        for token in tokens:
            if '(out)' in token: more_out_args.append(token.replace('(out)', ''))
            if '(in)' in token: more_in_args.append(token.replace('(in)', ''))
            if '(ignore)' in token: ignore_args.append(token.replace('(ignore)', ''))
        self.current_annotation_info = AnnotationInfo(not ('(assign)' in line), ignore_args, more_out_args, more_in_args)
        self.translation_status = TranslationStatus.TRANSLATING_FUNC_BODY_WITH_ANNOTATION

    def special_process_struct(self, line):
        if '{' in line: # start of struct 
            for struct_type in self.struct_types: line = line.replace(struct_type + ' ', '')
            replacements = {'typedef ' : '', '__packed ' : ''}
            line = reduce(lambda temp, repl: temp.replace(*repl), replacements.items(), line)
        elif '}' in line: line = line # end of struct
        else: # var declar
            for var_type in self.var_types: line = line.replace(var_type, 'var')
            if '[' in line and ']' in line: line = line[:line.find('[')] + line[line.find(']') + 1:]
        return line

    def special_process_func_start(self, line):
        if 'static' in line: # start of func
            for var_type in self.var_types: line = line.replace(var_type + ' ', '')
            replacements = {'const ' : '', 'static ' : '', '(' : ' ('}
            line = reduce(lambda temp, repl: temp.replace(*repl), replacements.items(), line)
            self.translation_status = TranslationStatus.TRANSLATING_FUNC_BODY_WITHOUT_ANNOTATION
        elif 'TA_CreateEntryPoint' in line or 'TA_DestroyEntryPoint' in line:
            tokens = line.split()
            line = tokens[1].replace('(void)', '') + ' ()'
            self.translation_status = TranslationStatus.TRANSLATING_FUNC_BODY_WITHOUT_ANNOTATION
        return line

    def special_process_func_body(self, line):
        if ':' in line: line = self.write_constants['tab'] + line.replace(':', ' :') # code label (case not considered yet)
        elif 'if (' in line: line = line.replace('!', '! ') # if statement
        elif '}\n' in line: line = line.replace('}', '} ;')
        else: # middle of func
            if self.translation_status == TranslationStatus.TRANSLATING_FUNC_BODY_WITH_ANNOTATION:
                if ' = ' in line and self.current_annotation_info.del_assign:
                    tokens = line.split()
                    line = line.replace(tokens[0] + ' ' + tokens[1] + ' ', '')
                for ignore_arg in self.current_annotation_info.ignore_args: line = line.replace(ignore_arg, '')
                for more_in_arg in self.current_annotation_info.more_in_args: line = line.replace(')', more_in_arg + ')')
                for (o_idx, more_out_arg) in enumerate(self.current_annotation_info.more_out_args):
                    if o_idx == 0: line = line.replace(');', ' ; ' + more_out_arg + ');')
                    else: line = line.replace(');', ',' + more_out_arg + ');')
                for type_conversion in self.need_to_strip_type_conversions: line = line.replace(type_conversion, ' ')
                self.translation_status = TranslationStatus.TRANSLATING_FUNC_BODY_WITHOUT_ANNOTATION
                self.current_annotation_info = None
            else: # self.translation_status == TranslationStatus.TRANSLATING_FUNC_BODY_WITHOUT_ANNOTATION
                if line.strip() == ';': return line.replace(';', 'skip') # do nothing line
                for type_conversion in self.need_to_strip_type_conversions: line = line.replace(type_conversion, ' ')
                for struct_type in self.struct_types:
                    if struct_type in line: line = line.replace(struct_type, 'struct ' + self.translate_mapping[struct_type])
                for var_type in self.var_types: line = line.replace(var_type, 'var')
                if 'var' in line and 'const' in line: line = line.replace('const ', '')
                if 'var' in line and '[' in line and ']' in line: line = line[:line.find('[')] + line[line.find(']') + 1:]
        return line

    def translate(self, source_path, target_path, custom_main):
        source_program = open(source_path)
        target_program = open(target_path, 'w')

        for line in source_program.readlines():
            if '//@add_line' in line: line = self.write_constants['tab'] + self.write_constants['tab'] + line.split(' | ')[1]
            if '//@create_custom_main' in line:
                custom_main_file = open(custom_main)
                for line in custom_main_file.readlines(): target_program.write(line)
                break

            # process user added preprocess comment
            self.process_preprocess_line(line)

            if self.translation_status == TranslationStatus.NOT_TRANSLATING: continue
            elif self.translation_status == TranslationStatus.TRANSLATING_STRUCT:
                line = self.special_process_struct(line)
            elif self.translation_status == TranslationStatus.TRANSLATING_FUNC_START:
                line = self.special_process_func_start(line)    
            elif self.translation_status == TranslationStatus.TRANSLATING_FUNC_BODY_WITHOUT_ANNOTATION or \
                self.translation_status == TranslationStatus.TRANSLATING_FUNC_BODY_WITH_ANNOTATION:
                if '//@func_annote' in line: self.process_func_annotation_line(line)
                else: 
                    if self.no_need_to_translate(line): continue
                    line = self.special_process_func_body(line)
            
            if self.no_need_to_translate(line): continue
            target_program.write(self.write_constants['tab'] + self.write_constants['tab'] + self.translate_to_imp(line))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    
    parser.add_argument('--source', default='./mqttz/preprocessed-ta.c')
    parser.add_argument('--target', default='./mqttz/imp.maude')
    parser.add_argument('-custom-main', default='./mqttz/custom_main.txt')

    args = parser.parse_args()

    translator = Translator()
    translator.translate(args.source, args.target, args.custom_main)
