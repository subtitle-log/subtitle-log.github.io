---
title: "HEVD 분석 #1 Stack Buffer Overflow"
summary: "커널 스택 오버플로우의 root cause와 익스 전략, 그리고 막힌 지점."
date: 2026-11-08
tags: ["HEVD", "Kernel"]
draft: true
category: Kernel
---

> 틀(템플릿)입니다. HEVD Stack Overflow 모듈을 분석하며 채워 넣으세요.

## 들어가며

- HEVD(HackSys Extreme Vulnerable Driver)가 무엇인지 1~2줄
- 이 글에서 다룰 것: Stack Overflow 모듈
- 환경: Windows / HEVD 버전 / WinDbg / VM

## 취약한 코드 경로

```c
// IOCTL 핸들러 → 취약 함수 → 크기 검증 없는 복사
```

## Root Cause

유저가 넘긴 크기를 검증하지 않고 커널 스택 버퍼에 복사 → 스택에서 무엇이 덮이는지.

## 트리거 & 익스 전략

- IOCTL을 날리는 유저 프로그램 구조
- 제어 흐름 탈취 개념
- 토큰 스틸링까지의 큰 그림

## 막힌 지점 & 완화 기법

- 어디까지 재현했고 어디서 멈췄는지 (솔직하게)
- SMEP / SMAP / kASLR 의 역할
- 다음 과제

## 정리

이 모듈에서 이해하게 된 핵심.


