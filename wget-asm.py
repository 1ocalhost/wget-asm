#!/usr/bin/python3

import argparse
import ipaddress
import os
import re
import socket
from types import SimpleNamespace
from urllib.parse import urlparse

import keystone

'''
pseudo code for executor:
    sockfd = socket(...)
    if sockfd < 0:
        goto exit

    if connect(sockfd, ...) < 0:
        goto exit

    if setsockopt(sockfd, SO_SNDTIMEO, ...) < 0:
        goto exit

    if setsockopt(sockfd, SO_RCVTIMEO, ...) < 0:
        goto exit

    if send(sockfd, ...) < 0:
        goto exit

    filefd = open(...)
    if filefd < 0:
        goto exit

    eat_http_header:
        num = recv(sockfd, buf, len=1, ...)
        if num < 1:
            goto exit
        if buf[0] != b'\n':
            goto eat_http_header
        num = recv(sockfd, buf, len=2, ...)
        if num < 2:
            goto exit
        if buf[:2] == b'\r\n':
            goto pipe_body
        goto eat_http_header

    pipe_body:
        num = recv(sockfd, buf, len=512, ...)
        if num < 1:
            goto exit
        num = write(filefd, buf, num)
        if num < 1:
            goto exit

    exit:
        if (sockfd) >= 0:
            shutdown(sockfd, ...)
            close(sockfd)
        if (filefd) >= 0:
            close(filefd)
'''

EXECUTOR_SRC_CODE = '''
    #define IO_TIMEOUT_SEC  5
    #define ARG_BUF_SIZE    64
    #define DATA_BUF_SIZE   512
    #define UNKNOW_ERROR    222

    #define SETSOCKOPT_ARGS $sockfd, SOL_SOCKET,
        SO_SNDTIMEO, $data_buf, sizeof(timeval)

    #define RECV_ARGS $sockfd, $data_buf, 1, MSG_WAITALL

    assign($sockfd, -1)
#ifdef MINI
    assign($filefd, 1)
#else
    assign($filefd, -1)
#endif

    socket_call(SYS_socket, AF_INET, SOCK_STREAM, 0)
    assign($sockfd, $return)
    goto_if_syscall_failed(exit)

    socket_call(SYS_connect, $sockfd, @remote_addr, sizeof(sockaddr_in))
    goto_if_syscall_failed(exit)

#ifndef MINI
    write_list($data_buf, 0, IO_TIMEOUT_SEC, 0)
    socket_call(SYS_setsockopt, SETSOCKOPT_ARGS)
    goto_if_syscall_failed(exit)

    socket_call_reuse_args(2, SO_RCVTIMEO, SYS_setsockopt, SETSOCKOPT_ARGS)
    goto_if_syscall_failed(exit)
#endif

    socket_call(SYS_send, $sockfd, @send_out_data, SEND_OUT_LEN, 0)
    goto_if_syscall_failed(exit)
    goto_if_less_than(unknow_error, $return, SEND_OUT_LEN)

#ifndef MINI
    syscall(SYS_open, @output_file, OPEN_FILE_FLAGS, OPEN_FILE_MODE)
    assign($filefd, $return)
    goto_if_syscall_failed(exit)
#endif

eat_http_header:
    socket_call(SYS_recv, RECV_ARGS)
    goto_if_syscall_failed(exit)
    goto_if_less_than(unknow_error, $return, 1)
    goto_if_data_not_equal(eat_http_header, $data_buf, 0, LINE_FEED)

    socket_call_reuse_args(2, 2, SYS_recv, RECV_ARGS)
    goto_if_syscall_failed(exit)
    goto_if_less_than(unknow_error, $return, 2)
    goto_if_data_not_equal(eat_http_header, $data_buf, 0, CARRIAGE_RETURN)
    goto_if_data_not_equal(eat_http_header, $data_buf, 1, LINE_FEED)
    goto(pipe_body)

pipe_body:
    socket_call_reuse_args(2, DATA_BUF_SIZE, SYS_recv, RECV_ARGS)
    goto_if_syscall_failed(exit)
    goto_if_less_than(exit_noraml, $return, 1)
    assign($data_len, $return)
    syscall(SYS_write, $filefd, $data_buf, $data_len)
    goto_if_syscall_failed(exit)
    goto_if_less_than(unknow_error, $return, $data_len)
    goto(pipe_body)

#ifdef MINI
exit:
unknow_error:
exit_noraml:
    syscall(SYS_exit, 0)
#else
exit:
    assign($errno, $return)
    goto_if_equal(unknow_error, $return, 0)
    goto(exit_close_sock)

unknow_error:
    assign($errno, UNKNOW_ERROR)
    goto(exit_close_sock)

exit_noraml:
    assign($errno, 0)

exit_close_sock:
    goto_if_less_than(exit_close_file, $sockfd, 0)
    socket_call(SYS_shutdown, $sockfd, SHUT_RDWR)
    syscall(SYS_close, $sockfd)

exit_close_file:
    goto_if_less_than(exit_program, $filefd, 0)
    syscall(SYS_close, $filefd)

exit_program:
    syscall(SYS_exit, $errno)
#endif
'''


class ExecutorImpl:
    LINE_FEED = ord('\n')
    CARRIAGE_RETURN = ord('\r')

    O_WRONLY = 0o01
    O_CREAT = 0o0100
    O_TRUNC = 0o1000

    S_IRWXU = 0o700
    S_IRWXG = 0o070
    S_IRWXO = 0o007
    OPEN_FILE_MODE = S_IRWXU | S_IRWXG | S_IRWXO

    AF_INET = 2
    SHUT_RDWR = 2
    MSG_WAITALL = 0x100

    SOCK_STREAM = 1
    SOL_SOCKET = 1
    SO_RCVTIMEO = 20
    SO_SNDTIMEO = 21

    SYS_SOCKET = 1
    SYS_CONNECT = 3
    SYS_SEND = 9
    SYS_RECV = 10
    SYS_SHUTDOWN = 13
    SYS_SETSOCKOPT = 14

    SIZEOF = {
        'sockaddr_in': 16,
        'timeval': 8,
    }

    def __init__(self):
        self.define = {
            **self._props(ExecutorImpl),
            **self._props(type(self)),
            **self.VARIABLES,
            '$errno': self.VARIABLES['$data_buf'],
        }

        del self.define['__module__']
        self.define['OPEN_FILE_FLAGS'] = \
            self.O_WRONLY | self.O_CREAT | self.O_TRUNC

        for key, value in self.SIZEOF.items():
            self.define[f'sizeof({key})'] = value

    @staticmethod
    def _props(type_):
        def is_prop(item):
            _, value = item
            return type(value) in (str, int)

        return dict(filter(is_prop, vars(type_).items()))

    @classmethod
    def _combine_impl(cls, result, statements):
        for item in statements:
            if isinstance(item, list):
                cls._combine_impl(result, item)
            elif item is not None:
                result.append(item)

    @classmethod
    def combine(cls, *statements):
        result = []
        cls._combine_impl(result, statements)
        return result

    @classmethod
    def assign(cls, dst, src):
        if dst != src:
            return cls.assign_impl(dst, src)

    @classmethod
    def goto_if_less_than(cls, label, value, baseline):
        assert value != baseline
        return cls.goto_if_less_than_impl(label, value, baseline)

    @classmethod
    def write_list(cls, target, offset, *args):
        offset = int(offset) * 4
        return cls.write_list_impl(target, offset, *args)

    @classmethod
    def syscall_impl(cls, reg_list, syscall, args):
        result = [
            cls.assign(reg_list[i], args[i])
            for i in range(len(args))
        ]

        result.append(syscall)
        return cls.combine(result)


class ExecutorImplX86(ExecutorImpl):
    SYS_exit = 0x01
    SYS_write = 0x04
    SYS_open = 0x05
    SYS_close = 0x06
    SYS_socketcall = 0x66

    VARIABLES = {
        '$sockfd': 'edi',
        '$filefd': 'esi',
        '$arg_buf': 'ebp',
        '$data_buf': 'esp',
        '$data_len': 'edx',
        '$return': 'eax',
    }

    @staticmethod
    def init():
        return [
            'sub $data_buf, ARG_BUF_SIZE',
            'mov $arg_buf, $data_buf',
            'sub $data_buf, DATA_BUF_SIZE',
        ]

    @staticmethod
    def goto(label):
        return f'jmp {label}'

    @staticmethod
    def assign_impl(dst, src):
        return f'mov {dst}, {src}'

    @staticmethod
    def goto_if_less_than_impl(label, value, baseline):
        return [
            f'cmp {value}, {baseline}',
            f'jl {label}',
        ]

    @classmethod
    def goto_if_syscall_failed(cls, label):
        return cls.goto_if_less_than(label, 'eax', 0)

    @staticmethod
    def goto_if_equal(label, variable, other):
        return [
            f'cmp {variable}, {other}',
            f'je {label}',
        ]

    @staticmethod
    def write_list_impl(target, offset, *values):
        result = []
        for src in values:
            dst = f'{target} + {offset}'
            result.append(f'mov dword ptr [{dst}], {src}')
            offset += 4

        return result

    @classmethod
    def syscall(cls, *args):
        return cls.syscall_impl(
            ['eax', 'ebx', 'ecx', 'edx'], 'int 0x80', args)

    @staticmethod
    def goto_if_data_not_equal(label, addr, offset, value):
        return [
            f'movzx eax, byte ptr [{addr} + {offset}]',
            f'cmp eax, {value}',
            f'jne {label}',
        ]


class ExecutorImplMips(ExecutorImpl):
    '''
        b       branch
        beq     branch equal
        blt     branch less than
        bne     branch not equal
        lb      load byte
        li      load immediate number
        sw      store word
    '''

    O_CREAT = 0x0100
    O_TRUNC = 0x0200

    SOCK_STREAM = 2
    SOL_SOCKET = 0xffff

    SO_SNDTIMEO = 0x1005
    SO_RCVTIMEO = 0x1006

    SYS_exit = 0xfa1
    SYS_write = 0xfa4
    SYS_open = 0xfa5
    SYS_close = 0xfa6
    SYS_socketcall = 0x1006
    SYS_socket = 0x1057
    SYS_connect = 0x104a
    SYS_send = 0x1052
    SYS_recv = 0x104f
    SYS_shutdown = 0x1056
    SYS_setsockopt = 0x1055

    VARIABLES = {
        '$sockfd': '$s0',
        '$filefd': '$s1',
        '$arg_buf': '$s2',
        '$data_buf': '$s3',
        '$data_len': '$s4',
        '$return': '$v0',
    }

    @staticmethod
    def init():
        return [
            'sub $arg_buf, $sp, ARG_BUF_SIZE',
            'sub $data_buf, $arg_buf, DATA_BUF_SIZE',
        ]

    @staticmethod
    def goto(label):
        return f'b {label}'

    @staticmethod
    def assign_impl(dst, src):
        if src.startswith('$'):
            return f'move {dst}, {src}'
        else:
            return f'li {dst}, {src}'

    @classmethod
    def goto_if_less_than_impl(cls, label, value, baseline):
        if baseline == '0':
            baseline = '$zero'

        if baseline.startswith('$'):
            return f'blt {value}, {baseline}, {label}'

        return cls.combine(
            f'li $t0, {baseline}',
            f'blt {value}, $t0, {label}',
        )

    @staticmethod
    def goto_if_syscall_failed(label):
        return f'bne $a3, $zero, {label}'

    @staticmethod
    def goto_if_equal(label, variable, other):
        assert other == '0'
        return f'beq {variable}, $zero, {label}'

    @classmethod
    def write_list_impl(cls, target, offset, *values):
        def store(value, dst):
            if value.startswith('$'):
                return f'sw {value}, {dst}'
            else:
                return [
                    f'li $t1, {value}',
                    f'sw $t1, {dst}',
                ]

        result = []
        for src in values:
            dst = f'{offset}({target})'
            result.append(store(src, dst))
            offset += 4

        return cls.combine(result)

    @classmethod
    def syscall(cls, *args):
        return cls.syscall_impl(
            ['$v0', '$a0', '$a1', '$a2', '$a3', '$t0'],
            'syscall', args
        )

    @staticmethod
    def goto_if_data_not_equal(label, addr, offset, value):
        return [
            f'lb $t0, {offset}({addr})',
            f'li $t1, {value}',
            f'bne $t0, $t1, {label}',
        ]


class ExecutorImplArm(ExecutorImpl):
    '''
        str     store
        ldrb    load byte
        [others are the same as MIPS]
    '''

    SYS_exit = 1
    SYS_write = 4
    SYS_open = 5
    SYS_close = 6
    SYS_socket = 281
    SYS_connect = 283
    SYS_send = 289
    SYS_recv = 291
    SYS_shutdown = 293
    SYS_setsockopt = 294

    VARIABLES = {
        '$sockfd': 'r8',
        '$filefd': 'r9',
        '$arg_buf': 'r10',
        '$data_buf': 'r11',
        '$data_len': 'r12',
        '$return': 'r0',
    }

    @staticmethod
    def init():
        return [
            'sub $arg_buf, r13, ARG_BUF_SIZE',
            'sub $data_buf, $arg_buf, DATA_BUF_SIZE',
        ]

    @staticmethod
    def goto(label):
        return f'b {label}'

    @staticmethod
    def assign_impl(dst, src):
        try:
            src_num = int(src)
            if src_num > 0xffff:
                # LDR pseudo-instruction
                return f'ldr {dst}, ={src}'
        except ValueError:
            pass

        return f'mov {dst}, {src}'

    @classmethod
    def goto_if_less_than_impl(cls, label, value, baseline):
        return [
            f'cmp {value}, {baseline}',
            f'blt {label}',
        ]

    @classmethod
    def goto_if_syscall_failed(cls, label):
        return cls.goto_if_less_than(label, 'r0', 0)

    @staticmethod
    def goto_if_equal(label, variable, other):
        return [
            f'cmp {variable}, {other}',
            f'beq {label}',
        ]

    @classmethod
    def write_list_impl(cls, target, offset, *values):
        def store(value, dst):
            try:
                value_num = int(value)
            except ValueError:
                return f'str {value}, {dst}'

            return [
                f'ldr r1, ={value_num}',
                f'str r1, {dst}',
            ]

        result = []
        for src in values:
            dst = f'[{target}, {offset}]'
            result.append(store(src, dst))
            offset += 4

        return cls.combine(result)

    @classmethod
    def syscall(cls, *args):
        return cls.syscall_impl(
            ['r7', 'r0', 'r1', 'r2', 'r3', 'r4'],
            'svc 0', args
        )

    @staticmethod
    def goto_if_data_not_equal(label, addr, offset, value):
        return [
            f'ldrb r1, [{addr}, {offset}]',
            f'cmp r1, {value}',
            f'bne {label}',
        ]


def new_elf32_file(arch):
    EM_386 = 3
    EM_MIPS = 8
    EM_ARM = 40
    EF_MIPS_ABI_O32 = 0x1000
    ELF_HEADER_SIZE = 0x54

    if arch.type == 'x86':
        arch_num = EM_386
        base_addr = 0x08048000
        e_flags = 0
    elif arch.type == 'arm':
        arch_num = EM_ARM
        base_addr = 0x08000000
        e_flags = 0
    elif arch.type == 'mips':
        arch_num = EM_MIPS
        base_addr = 0x400000
        e_flags = EF_MIPS_ABI_O32

    def to_bytes(len, num):
        return num.to_bytes(len, arch.endian)

    def elf32_hdr():
        ELFCLASS32 = 1
        ELFDATA2LSB = 1
        ELFDATA2MSB = 2
        ET_EXEC = 2

        if arch.endian == 'big':
            elf_data = ELFDATA2MSB
        else:
            elf_data = ELFDATA2LSB

        e_entry = base_addr + ELF_HEADER_SIZE

        yield b'\x7F' b'ELF'            # e_ident
        yield to_bytes(1, ELFCLASS32)
        yield to_bytes(1, elf_data)
        yield b'\x01'
        yield b'\x00' * 9

        yield to_bytes(2, ET_EXEC)      # e_type
        yield to_bytes(2, arch_num)     # e_machine
        yield to_bytes(4, 1)            # e_version
        yield to_bytes(4, e_entry)      # e_entry
        yield to_bytes(4, 0x34)         # e_phoff

        yield to_bytes(4, 0)            # e_shoff
        yield to_bytes(4, e_flags)      # e_flags
        yield to_bytes(2, 0x34)         # e_ehsize
        yield to_bytes(2, 0x20)         # e_phentsize
        yield to_bytes(2, 1)            # e_phnum
        yield to_bytes(2, 0)            # e_shentsize
        yield to_bytes(2, 0)            # e_shnum
        yield to_bytes(2, 0)            # e_shstrndx

    def elf32_phdr(file_size):
        PT_LOAD = 1
        PF_R = 0x4
        PF_X = 0x1

        yield to_bytes(4, PT_LOAD)      # p_type
        yield to_bytes(4, 0)            # p_offset
        yield to_bytes(4, base_addr)    # p_vaddr
        yield to_bytes(4, base_addr)    # p_paddr

        yield to_bytes(4, file_size)    # p_filesz
        yield to_bytes(4, file_size)    # p_memsz
        yield to_bytes(4, PF_R | PF_X)  # p_flags
        yield to_bytes(4, 0)            # p_align

    code_addr = base_addr + ELF_HEADER_SIZE

    def make(code, data):
        file_size = ELF_HEADER_SIZE + len(code) + len(data)
        hdr = b''.join(elf32_hdr())
        phdr = b''.join(elf32_phdr(file_size))
        header = hdr + phdr
        return header + code + data

    def data_addr(code):
        return code_addr + len(code)

    return SimpleNamespace(
            base_addr=base_addr,
            code_addr=code_addr,
            data_addr=data_addr,
            make=make,
        )


class ExecutorMaker:
    INDENT = ' ' * 4

    ALL_ARCH = {
        'x86': ('x86', 'little'),
        'arm': ('arm', 'little'),
        'armeb': ('arm', 'big'),
        'mips': ('mips', 'big'),
        'mipsel': ('mips', 'little'),
    }

    ARCH_TO_IMPL = {
        'x86': ExecutorImplX86,
        'mips': ExecutorImplMips,
        'arm': ExecutorImplArm,
    }

    def make(self, arch, url, output):
        self.mini_mode = not output
        self.arch = self._parse_arch(arch)
        impl_class = self.ARCH_TO_IMPL[self.arch.type]
        self.impl = impl_class()

        file = new_elf32_file(self.arch)
        fake_addr = file.code_addr
        static_data = self._make_static_data(url, output)
        send_len = len(static_data.send_out_data)
        semiproduct = self._assemble(
            fake_addr, fake_addr, send_len, fake_addr)

        remote_addr = file.data_addr(semiproduct)
        send_data = remote_addr + len(static_data.remote_addr)
        output_file = send_data + send_len
        product = self._assemble(
            remote_addr, send_data, send_len, output_file)

        assert len(semiproduct) == len(product)
        return file.make(product, static_data.all)

    @classmethod
    def _parse_arch(cls, arch):
        type, endian = cls.ALL_ARCH[arch]
        assert endian in ['big', 'little']
        return SimpleNamespace(type=type, endian=endian)

    def _make_static_data(self, url, output):
        if '://' not in url:
            url = f'http://{url}'

        url_obj = urlparse(url)
        assert url_obj.scheme == 'http'

        ip = socket.gethostbyname(url_obj.hostname)
        ip_bytes = int(ipaddress.IPv4Address(ip)).to_bytes(4, 'big')
        port = url_obj.port or 80
        port_bytes = port.to_bytes(2, 'big')
        sock_family = ExecutorImpl.AF_INET.to_bytes(2, self.arch.endian)
        remote_addr = sock_family + port_bytes + ip_bytes

        req_path = url_obj.path or '/'
        if url_obj.query:
            req_path = f'{req_path}?{url_obj.query}'

        send_out_data = '\r\n'.join([
                f'GET {req_path} HTTP/1.0',
                f'Host: {url_obj.hostname}',
                '\r\n',
            ]).encode()

        if self.mini_mode:
            output_file = b''
        else:
            output_file = output.encode() + b'\0'

        all = remote_addr + send_out_data + output_file

        return SimpleNamespace(
            remote_addr=remote_addr,
            send_out_data=send_out_data,
            output_file=output_file,
            all=all,
        )

    def _get_asm_code(self, remote_addr, send_data, send_len, out_file):
        define = self.impl.define
        define['SEND_OUT_LEN'] = send_len
        define['@remote_addr'] = remote_addr
        define['@send_out_data'] = send_data
        define['@output_file'] = out_file

        src_code = self._get_src_code()
        lines = self._join_continue_line(src_code)
        lines = self._handle_user_define(lines)

        lines = self._expand_line(
            lines, self._expand_user_define, self.user_define)

        lines = self._expand_line(lines, self._expand_socket_call)

        lines = self._expand_line(
            lines, self._compile_function, self.impl.define)

        return '\n'.join(lines)

    def _get_src_code(self):
        defined = []
        if self.mini_mode:
            defined.append('MINI')

        parts = []
        cur_part = ''
        for line in EXECUTOR_SRC_CODE.splitlines():
            if line.startswith('#if'):
                if cur_part:
                    parts.append(cur_part)
                cur_part = [line.strip(), []]
            elif line.startswith('#else'):
                cur_part.append([])
            elif line.startswith('#endif'):
                parts.append(cur_part)
                cur_part = ''
            else:
                if isinstance(cur_part, str):
                    cur_part += line
                    cur_part += '\n'
                else:
                    cur_part[-1].append(line)

        code = ''
        for part in parts:
            if isinstance(part, str):
                code += part
            else:
                if len(part) > 2:
                    define, face, opposite = part
                else:
                    define, face = part
                    opposite = []

                indicate, name = define.split(' ')

                if indicate == '#ifndef':
                    face, opposite = opposite, face
                else:
                    assert indicate == '#ifdef'

                content = face if name in defined else opposite
                content = '\n'.join(content)
                code += content
                if content:
                    code += '\n'

        init_code = self.impl.init()
        init_code_str = self._join_statements(init_code)
        return init_code_str + code

    @classmethod
    def _join_statements(cls, statements):
        if isinstance(statements, str):
            statements = [statements]

        statements = list(filter(None, statements))
        return '\n'.join(map(lambda x: cls.INDENT + x, statements))

    @classmethod
    def _join_continue_line(cls, code):
        result = []
        last_line = ''

        for line in code.splitlines():
            line_body = line.lstrip(' ')
            space_num = len(line) - len(line_body)

            if space_num > len(cls.INDENT):  # continue line
                assert last_line
                if last_line.rstrip().endswith(','):
                    last_line += ' '
                last_line += line_body
                continue

            if last_line:
                result.append(last_line)

            last_line = line

        result.append(last_line)
        return result

    def _handle_user_define(self, lines):
        define_lines = []
        general_lines = []

        for line in lines:
            if line.lstrip().startswith('#define'):
                define_lines.append(line)
            else:
                general_lines.append(line)

        def pop_token(group):
            target = group.lstrip()
            head = target.split(' ', 1)[0]
            rest = target[len(head):].lstrip()
            return head, rest

        self.user_define = {}

        for line in define_lines:
            _, rest = pop_token(line)
            name, value = pop_token(rest)
            self.user_define[name] = value

        return general_lines

    def _expand_user_define(self, _, name, args):
        new_args = self._replace_parts(args, self.user_define)
        return f'{name}({self.join_args(new_args)})'

    def _expand_socket_call(self, line, name, args):
        join_args = self.join_args
        if name == 'socket_call':
            call, *rest = args
            if self._syscall_arg_by_reg(call):
                return f'syscall({join_args(args)})'
            else:
                return [
                    f'write_list($arg_buf, 0, {join_args(rest)})',
                    f'syscall(SYS_socketcall, {call.upper()}, $arg_buf)',
                ]
        elif name == 'socket_call_reuse_args':
            arg_index, arg_value, call, *rest = args
            if self._syscall_arg_by_reg(call):
                rest[int(arg_index)] = arg_value
                return f'syscall({call}, {join_args(rest)})'
            else:
                return [
                    f'write_list($arg_buf, {arg_index}, {arg_value})',
                    f'syscall(SYS_socketcall, {call.upper()}, $arg_buf)',
                ]
        else:
            return line

    @staticmethod
    def join_args(args):
        return ', '.join(args)

    def _syscall_arg_by_reg(self, call):
        arch = self.arch.type
        if arch == 'mips' and call == 'SYS_setsockopt':
            return False

        return arch != 'x86'

    @staticmethod
    def _replace_parts(parts, table):
        def replace(src):
            target = table.get(src)
            if isinstance(target, int):
                target = str(target)
            return target if target else src

        return list(map(replace, parts))

    def _compile_function(self, _, name, args):
        new_args = self._replace_parts(args, self.impl.define)
        func = getattr(self.impl, name)
        result = func(*new_args)
        return result

    def _expand_line(self, lines, on_func, table=None):
        result = []

        for line in lines:
            new_line = self._expand_one_line(line, on_func, table)
            if new_line:
                result.extend(new_line.split('\n'))

        return result

    def _expand_one_line(self, line, on_func, table):
        statement = line.strip()

        # empty, comment
        if not statement or statement.startswith(';'):
            return

        # label
        if statement.endswith(':'):
            return line

        if not statement.endswith(')'):
            if table:
                parts = re.findall(r'[\w\$#]+|[^\w\$#]+', statement)
                new_parts = self._replace_parts(parts, table)
                return self.INDENT + ''.join(new_parts)
            else:
                return line

        func_name, func_args = statement[:-1].split('(', 1)
        func_args = self._parse_arg_list(func_args)
        result = on_func(statement, func_name, func_args)
        return self._join_statements(result)

    @staticmethod
    def _parse_arg_list(args):
        result = map(str.strip, args.split(','))
        return list(filter(None, result))

    def _assemble(self, *args):
        arch = self.arch.type
        if arch == 'x86':
            ks_arch = keystone.KS_ARCH_X86
            ks_mode = keystone.KS_MODE_32
        elif arch == 'arm':
            ks_arch = keystone.KS_ARCH_ARM
            ks_mode = keystone.KS_MODE_ARM
        elif arch == 'mips':
            ks_arch = keystone.KS_ARCH_MIPS
            ks_mode = keystone.KS_MODE_32

        if self.arch.endian == 'big':
            ks_mode |= keystone.KS_MODE_BIG_ENDIAN
        else:
            ks_mode |= keystone.KS_MODE_LITTLE_ENDIAN

        ks = keystone.Ks(ks_arch, ks_mode)
        asm_code = self._get_asm_code(*args)
        exec_code, _ = ks.asm(asm_code)
        exec_code = bytes(exec_code)
        return exec_code


def echo_encode(data):
    table = {
        0x07: 'a',
        0x08: 'b',
        0x09: 't',
        0x0A: 'n',
        0x0B: 'v',
        0x0C: 'f',
        0x0D: 'r',
        0x1B: 'E',
        0x1B: 'E',
        0x5C: '\\',
    }

    result = ''
    for i in data:
        if i in table:
            result += f'\\{table[i]}'
        elif 0x20 <= i <= 0x7E and i != ord("\'"):
            result += chr(i)
        else:
            result += f'\\x{"%02x" % i}'

    return f"echo -ne '{result}'"


def main():
    parser = argparse.ArgumentParser(prog='wget-asm.py')
    parser.add_argument(
        '--arch', help='target architecture for executor',
        default='x86', choices=ExecutorMaker.ALL_ARCH.keys())
    parser.add_argument(
        '--exe', help='file name for executor')
    parser.add_argument(
        '--out', help='the file to save response')
    parser.add_argument(
        '--mini', help='mini mode, stdout only, no timeout, error code, etc.',
        action='store_true')
    parser.add_argument('url', help='the request URL')

    args = parser.parse_args()

    if args.mini:
        if args.out is not None:
            print('mini mode: --out ignored')
        args.out = ''
    else:
        if args.out is None:
            STDOUT_FILE = '/proc/self/fd/1'
            args.out = STDOUT_FILE

    maker = ExecutorMaker()
    content = maker.make(args.arch, args.url, args.out)

    if args.exe:
        with open(args.exe, 'wb') as f:
            f.write(content)
        os.chmod(args.exe, 0o775)
    else:
        output = echo_encode(content)
        assert len(output) <= 8192, 'too big'
        print(output)


if __name__ == '__main__':
    main()
