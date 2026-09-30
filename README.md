# XOR-Decoder
난독화된 라이브러리 파일을 해석해주는 도구

Ghidra 디컴파일 XOR 디코딩 루틴을 바이너리에 적용해 결과 바이트를 계산한다.





사용법:
  python xor_decode.py decomp.txt target.bin --image-base 0x100000
  (target.bin 이 ELF이면 pyelftools 로 가상주소->파일오프셋 매핑, 없으면 --raw 로 평면 이미지 취급)

decomp.txt : 붙여넣은 디컴파일 텍스트를 저장한 파일
--image-base : Ghidra 표시주소 - 실제 가상주소 (PIE ELF 기본 0x100000)

pip install pyelftools 필요
