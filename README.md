# Decoder
xor_decode.py
------------------
.so 파일만으로(기기/에뮬레이터 불필요) 지정한 함수를 실제로 CPU 에뮬레이션(Unicorn Engine)
돌려서 실행시키고, 실행 전/후 메모리를 비교해 '함수가 어떤 바이트를 바꿨는지'를 자동으로
찾아내 hex/ascii 로 보여준다. XOR 뿐 아니라 어떤 방식으로 디코딩하든(루프, 레지스터 XOR 등)
실제 명령어를 그대로 실행하므로 정확하다.

설치:
    pip install unicorn pyelftools

사용법:
    python xor_decode.py <so파일명> <0x00123456> --image-base 0x100000

주의 / 한계:
  - 함수 인자(x0~x7)는 기본적으로 전부 0(NULL)으로 넣고 호출한다. 함수가 JNIEnv* 같은
    진짜 포인터를 역참조하는 코드라면 그 지점에서 바로 죽는다(비정상 종료로 보고됨).
    XOR 디코딩처럼 '전역 데이터만 건드리는 단순 초기화 루틴'일 때 가장 잘 작동한다.
  - 함수가 다른 함수를 호출(bl)하면 그 함수도 같은 메모리 공간 안에 있으면 따라 들어가
    실행된다. 외부(libc 등) 심볼을 호출하면 매핑이 없어 보통 그 시점에서 중단된다.
    이 경우에도 그때까지 바뀐 바이트는 결과에 포함되므로 부분 결과라도 의미가 있다.
  - 디버거 탐지, 안티후킹 같은 보호 로직을 우회하는 코드는 포함하지 않았다.


decode_all.py
------------------
.so 파일 하나만 주면:
  1) 심볼 테이블 + .text 프롤로그 휴리스틱으로 함수 목록을 뽑고
  2) 각 함수를 디스어셈블해서 ldrb/strb + eor/mvn 밀도로 'XOR 디코딩 루틴' 후보를 추리고
  3) 후보 함수들을 Unicorn 으로 실제 실행해서, 실행 전/후 바뀐 메모리를 찾아
  4) 어느 함수에서 나온 문자열인지와 함께 ascii 로 출력 + 파일 저장
까지 한 번에 처리한다. (기기/에뮬레이터 불필요)

설치:
    pip install capstone pyelftools unicorn

사용법:
    python decode_all.py <so파일명> --image-base 0x100000
    python decode_all.py <so파일명> --image-base 0x100000 --out strings.txt --top 20

