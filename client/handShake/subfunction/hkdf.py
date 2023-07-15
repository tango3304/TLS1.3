# Coding: UTF-8

# digest:https://zenn.dev/heku/articles/d850ac5c89b5da
# hmac.new:https://docs.python.org/ja/3/library/hmac.html

from hmac import new
from hashlib import sha256,sha384,sha512

# 疑似ランダムキー関数
def extract(salt_value, input_key_material, hashtype):
    if hashtype == "sha256":
        # HMACインスタンスを取得(sha256)
        pseudo_random_key = new(salt_value, input_key_material, sha256)
    elif hashtype == "sha384":
        # HMACインスタンスを取得(sha384)
        pseudo_random_key = new(salt_value, input_key_material, sha384)
    elif hashtype == "sha512":
        # HMACインスタンスを取得(sha512)
        pseudo_random_key = new(salt_value, input_key_material, sha512)
    
    # ダイジェスト値の計算(byte列)
    return pseudo_random_key.digest()

# 要素キーを導入
def derive_secret(pseudo_random_key, label, context, hashtype):
    if hashtype == "sha256":
        key_length = 32
    elif hashtype == "sha384":
        key_length = 48
    elif hashtype == "sha512":
        key_length = 64

    return expand_label(pseudo_random_key, label, transcript_hash(context, hashtype), key_length, hashtype)

# ダイジェスト値(ハッシュ値)を取得(contextがlist型かを確認)
def transcript_hash(context, hashtype):
    if type(context) is list:
        context = b''.join(context)
    if hashtype == "sha256":
        digest_value = sha256(context).digest()
    elif hashtype == "sha384":
        digest_value = sha384(context).digest()
    elif hashtype == "sha512":
        digest_value = sha512(context).digest()

    return digest_value

# スケジュールキー
def expand_label(pseudo_random_key, label, context, key_length, hashtype):
    label = b"tls13 " + label
    key_infomation = key_length.to_bytes(2,'big') + len(label).to_bytes(1,'big') + label + len(context).to_bytes(1,'big') + context
    
    return expand(pseudo_random_key, key_infomation, key_length, hashtype)

# 疑似ランダムキーでHMACハッシュ値を取得
def expand(pseudo_random_key, key_infomation, key_length, hashtype):
    t = b''
    t_1 = b''
    count = 0

    if hashtype == "sha256":
        while len(t) < key_length:
            count += 1
            hmac_instance = new(pseudo_random_key, t_1+key_infomation+count.to_bytes(1,'big'), sha256)
            t_1 = hmac_instance.digest()
            t += t_1
    elif hashtype == "sha384":
        while len(t) < key_length:
            count += 1
            hmac_instance = new(pseudo_random_key, t_1+key_infomation+count.to_bytes(1,'big'), sha384)
            t_1 = hmac_instance.digest()
            t += t_1
    elif hashtype == "sha512":
        while len(t) < key_length:
            count += 1
            hmac_instance = new(pseudo_random_key, t_1+key_infomation+count.to_bytes(1,'big'), sha512)
            t_1 = hmac_instance.digest()
            t += t_1

    # スライス
    # https://qiita.com/tanuk1647/items/276d2be36f5abb8ea52e
    output_key_material = t[:key_length]
    return output_key_material