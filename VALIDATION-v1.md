# 검증 기록 v1 — 2026-10-21

- 테스트 환경: 외부 Windows PC, Node.js. 내부망에서는 실행하지 않음.
- GitHub: https://github.com/ithing-goon/receive-only-updater-demo
- 단위/통합 테스트: node --test updater.test.mjs, 18개 통과.
- 실제 GitHub raw HTTPS 수신: version 1, 13 bytes, status verified.
- Ed25519 서명 및 SHA-256 검증 성공.
- 실제 파일 내용: Hello World! 및 LF.
- SHA-256: 03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340
- PowerShell 실행기를 통한 두 번째 실행: already-current. 로컬 파일 재검증 성공.
- GitHub 인증, Git 명령, 업로드를 수신 실행에 사용하지 않음.
- 서명용 개인키는 외부 Ubuntu 서버에 보관. 공개 저장소와 수신 패키지에 없음.
- 내부망 접근 허용 여부, OS 계정 격리, 패키지 자체 암호화는 미검증/미구현.
- 403 및 리디렉션 발생 시 중단하는 동작은 모의 전송 테스트로 검증. 보안 정책 우회 기능 없음.
- 배포 manifest는 생성 시점부터 7일 후 만료. 갱신은 외부에서 버전을 증가시켜 재서명해야 함.

