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

            # ignore TEE API func. not supported
            'TEE_Free(',            # so to not confuse with TEE_FreeTransient
            'TEE_GetSystemTime',
            'TEE_TIME_SUB'
        ]

        self.need_to_strip_chars = [
            '*', '&' # pointer currently not supported
            
        ]

        self.need_to_strip_type_conversions = [ # type conversion currently not supported
            ' (aes_cipher *)'
        ]

        self.var_types = [
            'uint32_t',             # C native
            'size_t',
            'void',
            'char',
            'int',

            'TEE_OperationHandle',  # TEE types
            'TEE_ObjectHandle',
            'TEE_Result',
            'TEE_Attribute'
        ]

        self.struct_types = [       # TODO: accumulate struct types as translating
            'TEE_ObjectInfo',       # currently manually added
            'aes_cipher'
        ]

        self.translate_mapping = {
            #TODO: need to update
            'payload_reencryption (*session, param_types, TEE_Param params[4])'
            : 'payload_reencryption (*session, ori_cli_id, ori_cli_iv, ori_cli_data, dest_cli_id, dest_cli_data)',
            '(var *) TEE_Malloc(sizeof *dest_cli_iv * (TA_AES_IV_SIZE + 1), 0);' : '# dummyIv;',
            '(var *) TEE_Malloc(sizeof *ori_cli_key * (TA_AES_KEY_SIZE + 1), 0);' : '# randomAttrVal;',
            '(var *) TEE_Malloc(sizeof *dest_cli_key * (TA_AES_KEY_SIZE + 1), 0);' : '# randomAttrVal;',
            '(var * ori_cli_iv) TEE_Malloc(sizeof *dec_data * dec_data_size, 0 ori_cli_iv);' : '# noData;',

            # C syntax to IMP syntax
            '->' : ' . ', 
            ' = ' : ' := ',
            ' == ' : ' === ',
            
            ' 0' : ' # 0',
            ' 1' : ' # 1',

            # TEE constant translate
            'TEE_STORAGE_PRIVATE' : '# TEE-STORAGE-PRIVATE',

            'TEE_HANDLE_NULL' : '# TEE-HANDLE-NULL',

            # 'TEE_DATA_FLAG_ACCESS_READ'         : '# TEE-DATA-FLAG-ACCESS-READ',
            # 'TEE_DATA_FLAG_SHARE_READ'          : '# TEE-DATA-FLAG-SHARE-READ',
            # 'TEE_DATA_FLAG_ACCESS_WRITE'        : '# TEE-DATA-FLAG-ACCESS-WRITE',
            # 'TEE_DATA_FLAG_ACCESS_WRITE_META'   : '# TEE-DATA-FLAG-ACCESS-WRITE-META',
            # 'TEE_DATA_FLAG_OVERWRITE'           : '# TEE-DATA-FLAG-SHARE-WRITE',
            'TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ'
            : '# (TEE-DATA-FLAG-ACCESS-READ, TEE-DATA-FLAG-SHARE-READ)',
            'TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE'
            : '# (TEE-DATA-FLAG-ACCESS-READ, TEE-DATA-FLAG-ACCESS-WRITE, TEE-DATA-FLAG-ACCESS-WRITE-META, TEE-DATA-FLAG-OVERWRITE)',


            'TEE_TYPE_AES'                      : '# TEE-TYPE-AES',

            'TEE_ObjectInfo'    : 'TeeObjectInfo',
            'aes_cipher'        : 'AesCipher',

            'TEE_ATTR_SECRET_VALUE' : '# TEE-ATTR-SECRET-VALUE',

            'TEE_ALG_AES_CBC_NOPAD' : '# TEE-ALG-AES-CBC-NOPAD',

            'TEE_MODE_ENCRYPT' : '# TEE-MODE-ENCRYPT',
            'TEE_MODE_DECRYPT' : '# TEE-MODE-DECRYPT',

            'TEE_ERROR_BAD_PARAMETER'   : '# TEE-ERROR-BAD-PARAMETER',
            'TEE_ERROR_GENERIC'         : '# TEE-ERROR-GENERIC',
            'TEE_ERROR_OUT_OF_MEMORY'   : '# TEE-ERROR-OUT-OF-MEMORY',
            'TEE_ERROR_SHORT_BUFFER'    : '# TEE-ERROR-SHORT-BUFFER',
            'TEE_ERROR_BAD_STATE'       : '# TEE-ERROR-BAD-STATE',
            'TEE_ERROR_NOT_SUPPORTED'   : '# TEE-ERROR-NOT-SUPPORTED',

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

            # Custom constants translate
            'TA_AES_KEY_SIZE'                       : '# TA-AES-KEY-SIZE',
            'TA_AES_MODE_ENCODE'                    : '# TA-AES-MODE-ENCODE',
            'TA_AES_MODE_DECODE'                    : '# TA-AES-MODE-DECODE',
            'TA_REENCRYPT'                          : '# TA-REENCRYPT'
        }

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

    def process_preprocess_line(self, line, ignore_flag, struct_flag, func_flag):
        def is_preprocess_line(line): return ('//@' in line)

        def start_ignore(line): return ('//@ignore' in line)    
        def end_ignore(line): return ('//@endignore' in line)

        def start_process_struct(line): return ('//@process_struct' in line)
        def end_process_struct(line): return ('//@endprocess_struct' in line)

        def start_process_func(line): return ('//@process_func' in line)

        if not is_preprocess_line(line): pass # normal C line
        else: # is preprocess line
            if start_ignore(line): ignore_flag = True
            elif end_ignore(line): ignore_flag = False
            elif start_process_struct(line): struct_flag = True
            elif end_process_struct(line): struct_flag = False
            elif start_process_func(line): func_flag = True
            else: pass
        return [ignore_flag, struct_flag, func_flag]

    def process_func_annotation_line(self, line, annotation_info):
        def is_func_annotation(line): return ('//@func_annote' in line)

        if not is_func_annotation(line): return [False, annotation_info]
        else:
            ignore_args, more_out_args, more_in_args = [], [], []
            tokens = line.split('|')
            for token in tokens:
                if '(out)' in token: more_out_args.append(token.replace('(out)', ''))
                if '(in)' in token: more_in_args.append(token.replace('(in)', ''))
                if '(ignore)' in token: ignore_args.append(token.replace('(ignore)', ''))
            return [True, AnnotationInfo(not ('(assign)' in line), ignore_args, more_out_args, more_in_args)]

    def special_process_struct(self, line):
        if '{' in line: # start of struct 
            for struct_type in self.struct_types: line = line.replace(struct_type + ' ', '')
            line = line.replace('typedef ', '')
        elif '}' in line: line = line # end of struct
        else: # var declar
            for var_type in self.var_types: line = line.replace(var_type, 'var')
        return line

    def special_process_func(self, line, annotation_info=None):
        if 'static' in line: # start of func
            for var_type in self.var_types: line = line.replace(var_type + ' ', '')
            line = line.replace('static ', '')
            line = line.replace('(', ' (')
        elif ':' in line: line = self.write_constants['tab'] + line.replace(':', ' :') # code label (case not considered yet)
        elif 'if' in line: line = line.replace('!', '! ') # if statement
        elif '}\n' in line: line = line.replace('}', '} ;')
        else: # middle of func
            if annotation_info is not None:
                if ' = ' in line and annotation_info.del_assign:
                    tokens = line.split()
                    line = line.replace(tokens[0] + ' ' + tokens[1] + ' ', '')
                for ignore_arg in annotation_info.ignore_args: line = line.replace(ignore_arg, '')
                for more_in_arg in annotation_info.more_in_args: line = line.replace(')', more_in_arg + ')')
                for (o_idx, more_out_arg) in enumerate(annotation_info.more_out_args):
                    if o_idx == 0: line = line.replace(');', ' ; ' + more_out_arg + ');')
                    else: line = line.replace(');', ',' + more_out_arg + ');')
                annotation_info.del_assign = False

            for type_conversion in self.need_to_strip_type_conversions: line = line.replace(type_conversion, ' ')
            for struct_type in self.struct_types:
                if struct_type in line: line = line.replace(struct_type, 'struct ' + self.translate_mapping[struct_type])
            for var_type in self.var_types: line = line.replace(var_type, 'var')
        return line

    def translate(self, source_path='./preprocessed-ta.c', target_path='./imp.maude'):
        source_program = open(source_path)
        target_program = open(target_path, 'w')

        ignore_flag, struct_flag, func_flag = False, False, False
        annotation_encounted, annotation_info = False, None
        for line in source_program.readlines():
            # process user added preprocess comment
            [ignore_flag, struct_flag, func_flag] = self.process_preprocess_line(line, ignore_flag, struct_flag, func_flag)
            [annotation_encounted, annotation_info] = self.process_func_annotation_line(line, annotation_info)
            if ignore_flag: continue 

            if '//@create_custom_main' in line:
                custom_main_file = open('./custom_main.txt')
                for line in custom_main_file.readlines(): target_program.write(line)
                break
            if '//@add_line' in line: line = self.write_constants['tab'] + self.write_constants['tab'] + line.split(' | ')[1]

            if self.no_need_to_translate(line): continue
            else: 
                if struct_flag: line = self.special_process_struct(line)
                if func_flag: line = self.special_process_func(line, annotation_info)
                target_program.write(self.write_constants['tab'] + self.write_constants['tab'] + self.translate_to_imp(line))

if __name__ == '__main__':
    translator = Translator()
    translator.translate()

