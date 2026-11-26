# Subtitle Log

Astro로 개발한 취약점 연구 기록용 사이트

마크다운 파일을 추가하면 목록과 글 페이지가 자동으로 생성된다.

## 실행

```bash
npm install      # 최초 1번
npm run dev      # 로컬 미리보기(localhost:4321)
npm run build    # 배포용 빌드 (dist/)
npm run preview  # 빌드 결과 확인
```

## 글 추가

- 연구 기록: `src/content/research/` 에 `.md` 추가
- 분석 글: `src/content/analysis/` 에 `.md` 추가

파일 맨 위 형식:

```markdown
---
title: "제목"
date: 2026-11-16
category: "Kernel"   # Kernel | CVE | Reversing | Tooling | Notes
featured: false      # true 면 홈 Featured Posts 에 노출 (최대 3개)
draft: false         # true 면 사이트에 안 나옴
---

본문
```

글 양식 전체는 `src/content/_template.md` 에 정리되어 있다. 복사해서 쓰면 된다.

`summary` 와 `tags` 는 선택 항목이다. 홈의 Latest Entries 에는 날짜순으로 자동 반영되고,

Featured Posts 에는 `featured: true` 인 글만 올라간다.

## 카테고리 관리

카테고리는 두 곳에서 관리된다.

1. **카테고리 페이지:** `src/pages/` 아래에 카테고리별 `.astro` 파일이 있다 (kernel.astro, cve.astro, reversing.astro, tooling.astro, notes.astro). 각 파일 안에서 `const CATEGORY = 'Kernel'` 같은 값으로 해당 카테고리의 글만 필터링한다.
2. **홈 네비게이션:** `src/pages/index.astro` 의 `keys` 배열에 카테고리 이름과 링크가 등록되어 있다.

새 카테고리 추가:
- 기존 카테고리 `.astro` 파일을 복사해서 `src/pages/<name>.astro` 생성
- 파일 안의 `CATEGORY` 값을 새 카테고리 이름으로 변경
- `index.astro` 의 `keys` 배열에 항목 추가

카테고리 삭제:
- 해당 `.astro` 파일 삭제
- `index.astro` 의 `keys` 배열에서 항목 제거

글의 frontmatter `category` 값은 자유 텍스트이므로, 카테고리 페이지가 없는 값을 쓰면 홈 네비게이션에서 연결이 안 된다.

## 비공개

- 사이트에서만 숨기기: `draft: true`
- 아예 커밋하지 않기: `drafts/` 폴더에 두면 `.gitignore` 로 제외된다. 공개 전 PoC나 민감한 자료는 여기에.

## 검색

홈 상단 검색창에서 글 제목, 카테고리, 태그로 검색할 수 있다.

## 배포

`main` 에 push 하면 `.github/workflows/deploy.yml` 가 빌드 후 GitHub Pages 에 배포한다. 저장소 Settings → Pages → Source 를 "GitHub Actions" 로 한 번 설정해 두어야 한다.
