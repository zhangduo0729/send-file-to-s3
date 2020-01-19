#!/usr/bin/env python
# -*- coding: utf-8 -*-


import os
from bottle import *
import json
import base64
import hmac
import boto3
from botocore.client import Config

base_path = os.path.dirname(os.path.realpath(__file__))  # 获取脚本路径

upload_path = os.path.join(base_path, 'upload_path')   # 上传文件目录

if not os.path.exists(upload_path):
    os.makedirs(upload_path)

@route('/upload', method='POST')
def do_upload():
    filedata = request.files.get('uploadFile')
    token = request.params.get('token')
    print('token : {}'.format(token))
    if not certify_token("123",token):
        return json.dumps({'code': 401,'msg': 'token 验证失败'})

    s3 = boto3.resource('s3', config=Config(signature_version='s3v4'))
    try:
        if filedata.file:
            file_name = os.path.join(upload_path, filedata.filename)
            try:
                filedata.save(file_name)  # 保存到本地
            except IOError:
                return json.dumps({'code': 500,'msg': '已上传此文件，{}'.format(filedata.filename)})

            deci(file_name) #解密
            try:
                s3.meta.client.upload_file(file_name, 'extdata/jingxia/', filedata.filename) #上传到S3
            except IOError:
                return '上传失败'
            os.remove(file_name) #删除本地文件
            return json.dumps({'code': 200,'msg': '成功'})
        else:
            return json.dumps({'code': 400,'msg': '非文件'})
    except Exception as e:
            return json.dumps({'code': 400,'msg': '空文件'})

@route('/token', method='GET')
def do_upload():
    key = request.params.get('key')
    token = generate_token(key)
    print('token : {}'.format(token))
    return json.dumps({'code': 200,'msg': format(token)})

def encry(cnf_org):
    f_org = open(cnf_org,'r')
    content = f_org.read()
    content1 = content.encode(encoding='utf-8')
    content2 = base64.b64encode(content1)
    f_org.close()
    with open(cnf_org,'wb+') as f_org:
        f_org.write(content2)
 
def deci(cnf_now):
    f_now = open(cnf_now,'r')
    content = f_now.read()
    content1 = base64.b64decode(content)
    with open(cnf_now,'wb+') as f_now:
        f_now.write(content1)

def generate_token(key):
    """
    @Args:
        key: str (用户给定的key，需要用户保存以便之后验证token,每次产生token时的key 都可以是同一个key)
    @Return:
        state: str
    :param key:
    :param expire:
    :return:
    """
    ts_str = str(time.time())
    ts_byte = ts_str.encode("utf-8")
    sha1_tshex_str = hmac.new(key.encode("utf-8"), ts_byte, 'sha1').hexdigest()
    token = ts_str+':'+sha1_tshex_str
    b64_token = base64.urlsafe_b64encode(token.encode("utf-8"))
    return b64_token.decode("utf-8")

def certify_token(key, token):
    """
    @Args:
        key: str
        token: str
    @Returns:
        boolean
    :param key:
    :param token:
    :return:
    """
    token_str = base64.urlsafe_b64decode(token).decode('utf-8')
    token_list = token_str.split(':')
    if len(token_list) != 2:
        return False
    ts_str = token_list[0]
    known_sha1_tsstr = token_list[1]
    sha1 = hmac.new(key.encode("utf-8"), ts_str.encode('utf-8'), 'sha1')
    calc_sha1_tsstr = sha1.hexdigest()
    if calc_sha1_tsstr != known_sha1_tsstr:
        # token certification failed
        return False
    # token certification success
    return True

@error(404)
def error404(error):
    """处理错误信息"""
    return json.dumps({'code': 404,'msg': '请求错误'})

run(host="0.0.0.0",port=6009, reloader=False)
