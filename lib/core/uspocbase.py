# -*- coding:utf-8 -*-

"""
Copyright (c) 2015 UScanner developers
Author: ccSec <cc@uscanner.cc>
Create time: 2016.5.5
"""

"""
插件基类
"""

from abc import ABCMeta, abstractmethod

class USLevel(object):
    high = 'H'
    medium = 'M'
    low = 'L'
    notice = 'N'

class USType(object):
    host = 'H'
    app = 'A'
    web = 'W'

class USCategory(object):
    injection = '注入'
    xss = 'xss跨站脚本攻击'
    xxe = 'xml外部实体攻击'
    file_upload = '任意文件上传'
    file_operation = '任意文件操作'
    file_traversal = '目录遍历'
    rce = '远程命令/代码执行'
    lfi = '本地文件包含'
    rfi = '远程文件包含'
    info_leak = '信息泄漏'
    misconfiguration = '错误配置'
    other = '其他'

class USResult(object):
    level = 'level'
    data = 'data'
    desc = 'description'

class HostParams(object):
    str_ip = "ip"
    int_port = "port"
    str_type = "type"
    str_service = "service"
    str_product = "product"
    str_version = "version"
    str_os = "os"
    list_dict = "dict"

class AppParams(object):
    str_appname = "name"
    str_appversion = "version"
    str_url = "url"
    list_dict = "dict"

class WebParams(object):
    str_url = "url"
    str_request_header = "request_header"
    str_request_body = "request_body"
    list_dict = "dict"

class USParams(object):
    web = WebParams()
    app = AppParams()
    host = HostParams()

class USPocBase(object):
    __metaclass__ = ABCMeta

    def __init__(self):
        super(USPocBase, self).__init__()
        self.info = {}
        self.params = {}
        self.result_formats = {}
        self.results = []

    def register_params(self, dict_params, dict_args):
        assert isinstance(dict_params, dict)
        assert isinstance(dict_args, dict)
        mapping = {
                     USType.host    : HostParams,
                     USType.app     : AppParams,
                     USType.web     : WebParams
                  }
        plugin_type = self.info.get('type', None)
        for k, v in vars(mapping[plugin_type]).items():
            if not isinstance(v, str):
                continue
            op = str(k).split('_', 1)[0]
            if op not in ('bool', 'str', 'int', 'list'):
                continue
            if dict_params.has_key(v):
                if op == "int" and str(dict_params.get(v, None)).isdigit() == False:
                    exit("Error 001 : Param %s's default value is not int type."%k)
                self.params[v] = globals()['__builtins__'][op](dict_args.get(v, dict_params[v]))

    def register_result(self, dict_results):
        assert isinstance(dict_results, dict)
        if len(dict_results) == 0:
            exit("Error 002 : self.register_result's data is null.")
        for k, v in dict_results.items():
            if not v.has_key(USResult.desc):
                exit("Error 005 : USResult.desc must be required.")
        self.result_formats = dict_results
        #Check params
        mapping = {"name" : str,
                   "author": str,
                   "product": str,
                   "product_version": str,
                   "ref": list,
                   "official_link": str,
                   "type": str,
                   "category": str,
                   "level": str,
                   "create_date": str,
                   "description": str,
                   "require_libs": list}
        for k, v in mapping.items():
            if not self.info.has_key(k):
                exit("Error 003 : self.info['%s'] is not exists."%k)
            if not isinstance(self.info[k], v):
                exit("Error 004 : Type of self.info['%s'] is invalid."%k)

    def append_result(self, level, desc, data = {}):
        if not self.result_formats.has_key(level):
            return False
        self.results.append({'level' : level,
                             'description' : desc,
                             'data' : data})
        return True

    def print_debug(self, content):
        pass

    @abstractmethod
    def assign(self):
        pass

    @abstractmethod
    def run(self):
        pass
