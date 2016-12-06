# -*- coding: utf-8 -*-
from lib.core.uspocbase import *

class USPlugin(USPocBase):
    def __init__(self, dict_args = {}):
        super(self.__class__, self).__init__()
        self.info = {
            "name" : '插件名称',                                #插件名称
            "author" : '插件作者',                              #作者名称
            "product" : '产品名称',                             #存在漏洞的产品
            "product_version" : '产品版本',                     #存在漏洞的版本号
            "ref" : ['http://www.example.com'],                 #引用的URL
            "official_link" : 'http://www.example.com',         #产品官网链接
            "type" : USType.app,                                #插件类型
            "category" : USCategory.injection,                  #漏洞类型
            "level" : USLevel.high,                             #漏洞级别
            "create_date" : '2016-09-08',                       #插件创建时间
            "description" : '''
            漏洞详细描述
            ''',                                                #插件描述
            "require_libs" : []                                 #插件需要的第三方模块
        }

        self.register_params({                                  #插件所需的参数
            USParams.app.str_appname : "wordpress",
            USParams.app.str_url : "http://127.0.0.1/",
            USParams.app.list_dict : []
        }, dict_args)

        self.register_result({                                  #插件返回的数据
            USLevel.high : {
                USResult.data : {
                    "user" : "",
                    "pass" : ""
                },
                USResult.desc : ""
            }
        })

    #验证函数，系统根据返回结果来确定是否调用该插件
    def assign(self):
        #if self.params[USParams.app.str_appname] == "wordpress":
        #    return True
        return False

    #漏洞利用函数
    def run(self):
        #res_data = {}
        #res_data['username'] = "root"
        #res_data['password'] = "password"
        #self.append_result(USLevel.high, '存在wordpress弱口令 User:root,Pass:password.', res_data)
        return self.results

if __name__ == "__main__":
    usplugin = USPlugin({USParams.app.str_appname : "wordpress", USParams.app.str_url : "http://127.0.0.1/wordpress/", USParams.app.list_dict : [ [['admin'],['password']] ]})
    if usplugin.assign() == True:
        print usplugin.run()