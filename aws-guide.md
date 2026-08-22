# AWS에서 Piccard paper 벤치마크 실행하기 — 운영 런북

## 0. 개요

로컬 Mac Studio 대신 EC2에서 `paper-v1` revision matrix **275셀**을 완주시키고,
봉인된 결과를 Mac으로 회수하는 절차입니다. 유일한 진입점은
`scripts/run_revision_benchmarks.py`입니다.

**전략: 싼 인스턴스에서 먼저 검증하고, 통과하면 본 런을 돌립니다.**

```
Phase A (검증)                          Phase B (본 런)
c8i.xlarge · ~$0.5 · ~2.5시간     →     c8i.8xlarge · ~$38 · ~23시간
빌드 → ctest → dry-run → toy 104셀       paper 275셀 → 검증 → seal
= "Linux에서 돌아간다"만 증명            = 논문에 쓸 실측
AMI를 구워 Phase B로 넘김                결과를 Mac으로 회수
```

Phase A는 **paper 런을 절대 돌리지 않습니다.** 목적은 빌드·테스트·orchestrator
동작이 Linux에서 성립하는지 확인하고, 그 환경을 AMI로 굳혀 Phase B가 곧바로
측정에 들어가게 하는 것입니다.

> **정정(2026-08-23).** 이 문서는 본 런이 "재시작이 불가능"하다고 적어 왔지만,
> §4.7의 `--resume`은 실제로 동작하며 완료가 독립적으로 재확인되는 셀을 보존한
> 채 이어서 실행합니다. 정확한 사실은 이렇습니다: **중단된 런은 `--resume`으로
> 이어받을 수 있고**, 다만 최초 런과 인자가 한 글자라도 다르거나 provenance가
> 바뀌면 resume이 `exit 2`로 거부합니다(그 경우에만 전액 재지출입니다). 사고가
> 났을 때 §4.7을 먼저 읽으십시오. 결과 루트를 지우거나 새 디렉터리로 다시
> 시작하는 것은 되돌릴 수 없으므로 마지막 수단입니다.

Phase A에서 걸러내는 것이 여전히 가장 싼 방어선입니다.

| 항목 | 값 |
|---|---|
| Region | us-east-1, on-demand |
| **Phase A (검증) 인스턴스** | **`c8i.xlarge`** (4 vCPU) — SMT 그대로, 30 GiB gp3 |
| **Phase B (측정) 인스턴스** | **`c8i.8xlarge`** (32 vCPU) — CoreCount=16 / ThreadsPerCore=1, 100 GiB gp3 |
| vCPU 한도 | **Phase B는 한도 ≥32 필요 — 신규 계정 기본값은 5** (Step 2(c)) |
| OpenFHE | **1.5.0** 태그 직접 빌드, Intel HEXL 미사용 |
| `--seed` | **20260729** 고정 |
| `--threads` | **16** (flooding 3셀과 sj16 calibrate만 2) |
| Matrix | **275셀 = 273 RUN + 2 NO_SPAWN** |
| 예상 소요 | Phase A ~2.5h + Phase B **~23.4h** (밴드 16~34h) |
| 예상 비용 | **~$39** (본 런 ~$35) |

**진행 순서:** Step 1 로컬 마무리 → Step 2 AWS 계정 준비(**vCPU 증설 요청 포함**)
→ Step 3 Phase A 검증 + AMI → Step 4 Phase B 측정 런 → Step 5 결과 회수 →
Step 6 정리.

> **Phase A와 Phase B의 인스턴스 크기가 다른 이유.** Phase A는 타이밍을 재지
> 않으므로 코어 수가 결과에 영향을 주지 않습니다. 빌드가 조금 느려질 뿐이라
> 가장 싼 축으로 갑니다. 반대로 Phase B는 `--threads=16`에 물리 16코어를 정확히
> 맞춰야 하고 SMT도 꺼야 합니다.

---

## Step 1 — 로컬 마무리 (Mac)

작업 디렉터리: `~/Documents/04-Dev/01-research/active/piccard`

### 1(a) 구현된 변경 커밋

워킹 트리에 두 묶음의 변경이 있고, 둘 다 **아직 커밋되지 않았습니다.**
paper 런은 수정된 tracked 파일이 있으면 거부하므로 반드시 커밋·push해야 합니다.

1. **AWS 준비 구현** (17개 파일) — matrix 확장(275셀), flooding threads
   리터럴화, `long` 타임아웃 클래스, sqrt 커버리지 확대(12셀 추가),
   sqrt/dynamic paper 프로파일 수정, 검증기 허용오차 보정.
2. **threshold k=256 활성화** (5개 파일, codex 세션에서 별도 구현·검증) —
   `noise_calibration.inc`에 `(Threshold, STD128, 16384, depth 21)` 측정 행
   추가, `bench_threshold.cpp`의 depth>21 거부 가드를 이 측정 구성에 한해 완화,
   `test_params.cpp` 회귀 테스트, `ThresholdRevisionAgreementCli` 신설,
   그리고 matrix에서 k=256 3셀을 **NO_SPAWN → RUN으로 복귀**.

**두 묶음이 합쳐진 결과가 현재 상태입니다: 275셀 = 273 RUN + 2 NO_SPAWN**
(NO_SPAWN 2셀은 `sj16::u=262144`, `u=1048576`).

```bash
cd ~/Documents/04-Dev/01-research/active/piccard

git add -A -- ':!.gitignore' ':!aws-guide.md'
git diff --cached --stat        # 의도한 파일만 있는지 눈으로 확인
git commit
git push origin main
```

`.gitignore`(무관한 `.omo` 1줄)와 untracked `aws-guide.md`는 제외합니다.
그 외에 의도하지 않은 파일이 섞였으면 `git restore --staged <file>`로 빼세요.

**확인:** `git status --short`에 ` M` 항목이 남지 않아야 하고(`??`는 무관),
push 후 GitHub의 `main` HEAD가 방금 커밋과 일치해야 합니다. Phase A 인스턴스는
이 커밋을 clone하므로, **push하지 않으면 검증 대상이 옛 코드가 됩니다.**

### 1(b) 데이터셋 3종 재생성 (seed 20260729)

현재 디스크의 DBLP 데이터셋은 `seed 7` / `pair_count 4448`이라 계약(10000)과
root seed(20260729) 양쪽 모두와 어긋납니다. **재생성 필수.**

전처리 파라미터는 repo에 고정되어 있습니다:

| | DBLP-ACM | Enron |
|---|---|---|
| `record_count` | 4910 | 10000 |
| `pair_count` / `requested_pair_count` | 10000 | 10000 |
| `original`/`retained_positive_count` | 2224 | 0 |
| `max_documents` | (없음) | 10000 |
| `min_related_pairs` | (없음) | 100 |

주의사항:

- 서브커맨드는 `dblp_acm`이 아니라 **`dblp-acm`**(하이픈).
- `enron`은 `--strict` 필수, `--universe`는 `{65536, 1048576}`만 허용.
- **출력 디렉터리가 이미 있으면 실패** — CLI에 `--overwrite`가 없습니다.
  기존 디렉터리를 먼저 옮기세요.
- DBLP 정본 source manifest는 `datasets/manifests/dblp_acm.source.tsv`(tracked).

> **⚠ `datasets/data/processed/dblp_acm_u65536` 경로는 영구 격리되어 있습니다.**
> `prepare_real_datasets.py:1103-1119`가 이 경로를 입력으로도 출력으로도
> 거부합니다 (구 `pair_count=4448` / `seed=7` 런이 암묵적 입력으로 되살아나는
> 것을 막는 장치, 최하위 writer 계층에 있어 CLI 우회 불가).
> **출력은 반드시 다른 디렉터리명을 쓰세요** — 아래는 `_paper` 접미사를
> 씁니다. manifest 내부의 `variant` 값은 디렉터리명과 무관하게
> `dblp_acm_u65536`으로 기록되므로 계약에는 영향이 없습니다.

```bash
SEED=20260729

python3 scripts/prepare_real_datasets.py dblp-acm \
    --source-manifest=datasets/manifests/dblp_acm.source.tsv \
    --output-dir=datasets/data/processed/dblp_acm_u65536_paper \
    --universe=65536 --pairs=10000 --seed=$SEED --strict

python3 scripts/prepare_real_datasets.py enron \
    --source-manifest=datasets/data/enron.source.tsv \
    --output-dir=datasets/data/processed/enron_u65536 \
    --universe=65536 --max-documents=10000 --pairs=10000 \
    --min-related-pairs=100 --seed=$SEED --strict

python3 scripts/prepare_real_datasets.py enron \
    --source-manifest=datasets/data/enron.source.tsv \
    --output-dir=datasets/data/processed/enron_u1048576 \
    --universe=1048576 --max-documents=10000 --pairs=10000 \
    --min-related-pairs=100 --seed=$SEED --strict
```

**확인 — 계약 루프:**

```bash
for v in dblp_acm_u65536_paper enron_u65536 enron_u1048576; do
  echo "== $v"
  grep -E '^(seed|record_count|pair_count|requested_pair_count|max_documents|min_related_pairs)\b' \
      datasets/data/processed/$v/dataset.manifest.tsv
done
```

세 변종 모두 `seed 20260729`, DBLP는 `pair_count 10000` / `record_count 4910`,
Enron 두 변종은 `requested_pair_count 10000` / `max_documents 10000` /
`min_related_pairs 100`이어야 합니다.

### 1(c) 전송용 아카이브 — S3도 IAM도 불필요

`datasets/data/processed`는 약 15 MB입니다. 2.5 GB `maildir` 원본은 Mac을
떠나지 않으므로 Enron 재배포 금지 조건도 자동으로 지켜집니다.

```bash
tar czf /tmp/piccard-processed.tar.gz -C datasets/data processed
ls -lh /tmp/piccard-processed.tar.gz
```

### 1(d) 로컬 최종 확인

```bash
cmake --build build -j8 && (cd build && ctest --output-on-failure)

python3 scripts/run_revision_benchmarks.py --mode=dry-run \
    --build-dir=$PWD/build --results-root=/private/tmp/rr-$(date +%s) \
    --seed=20260729 --threads=16

git status --short     # 수정된 tracked 파일이 없어야 함 (?? 는 무관)
```

**확인:**

```
100% tests passed, 0 tests failed out of 90
revision dry-run: 275 cells; spawned=0
```

> macOS에서 `/tmp`는 심볼릭 링크라 `--results-root` 부모 가드에 걸립니다 —
> `/private/tmp`(실디렉터리)나 `$HOME` 하위를 쓰세요. Linux에서는 `/tmp` 그대로
> 무방합니다.

---

## Step 2 — AWS 계정 준비 (최초 1회)

### 2(a) AWS CLI 로그인 — 먼저 이것부터

나머지 전부가 여기에 막힙니다. 셋업 스크립트도 자격 증명 없이는 아무것도 하지
않습니다.

```bash
aws sts get-caller-identity     # Account/Arn이 나오면 이미 로그인됨
```

`Unable to locate credentials`가 나오면 아래 중 하나로 로그인합니다:

| 방식 | 명령 | 쓰는 경우 |
|---|---|---|
| IAM Identity Center(SSO) | `aws configure sso` | 조직/학교 계정 (권장) |
| 브라우저 로그인 | `aws login` | CLI v2 최신 흐름 |
| 액세스 키 | `aws configure` | IAM 사용자 키를 직접 발급받은 경우 |

리전은 **`us-east-1`**, 출력 형식은 `json`으로 설정하세요.

> 참고: `~/.aws/sso/cache/kiro-auth-token.json`이 있어도 그건 Kiro(IDE)용
> 토큰이라 AWS CLI 자격 증명으로 쓰이지 않습니다. 별도 로그인이 필요합니다.

### 2(b) 셋업 스크립트 실행

로그인 후 아래 한 줄이면 ①예산 알람 ②키페어 ③보안그룹이 모두 만들어집니다.
**멱등**이라 여러 번 돌려도 안전하고, 이미 있는 리소스는 건너뜁니다.

```bash
bash ~/piccard-aws-step2-setup.sh
```

스크립트가 하는 일:

1. **예산 알람** `piccard-bench-monthly` — $100/월, 임계 **50 / 80 / 100%**,
   `heewonchung@jbnu.ac.kr`로 알림 (`NOTIFY_EMAIL` 환경변수로 변경 가능). 실패 후 1회 재시도를 흡수하는 금액입니다
   (재시작 불가라 재시도는 전액 재지출).
   권한 부족으로 실패하면 콘솔 경로를 안내합니다:
   **Billing and Cost Management → Budgets → Create budget** → *Cost budget* /
   *Monthly* / $100.
2. **SSH 키페어** `piccard-bench` → `~/.ssh/piccard-bench.pem` (mode 400).
   AWS에만 키가 있고 로컬 `.pem`이 없는 경우(private key는 재발급 불가)
   삭제·재생성 여부를 물어봅니다.
3. **보안그룹** `piccard-bench-sg` — **현재 공인 IP에서 tcp/22만** 개방.
   그 외 포트는 열지 않습니다.

마지막에 키페어·`.pem` 권한·인바운드 규칙을 출력하고, Step 3의
`run-instances` 명령을 실제 보안그룹 ID로 채워서 보여줍니다.

**확인:**

```
  [OK] 키페어 생성 및 저장: /Users/heewonchung/.ssh/piccard-bench.pem (1674 bytes, mode 400)
  [OK] 보안그룹 생성: sg-xxxxxxxx
  [OK] 인바운드 규칙 추가: tcp/22 from <내IP>/32
```

인바운드 목록에 **22번 외 다른 포트가 있으면 안 됩니다.**

> **공인 IP가 바뀌면 SSH가 막힙니다** (공유기 재시작, 다른 네트워크, 테더링).
> 그때는 스크립트를 다시 실행하면 새 IP 규칙이 추가됩니다.

> **빈 `.pem` 함정.** 자격 증명 없이 가이드의 옛 명령을 실행하면 리다이렉트가
> **0바이트 `.pem`을 mode 400으로** 남깁니다. 그 상태에서 재실행하면 이번엔
> 읽기 전용이라 `Permission denied`가 납니다. 스크립트는 0바이트 파일을 감지해
> 자동으로 지우고 진행합니다.

### 2(c) vCPU 한도 확인 및 증설 요청 — Phase B의 선행 조건

**지금 바로 요청하세요.** 승인까지 몇 시간~며칠 걸리므로, Phase A 검증을
진행하는 동안 병렬로 처리되게 하는 것이 맞습니다.

```bash
aws service-quotas get-service-quota --region us-east-1 \
  --service-code ec2 --quota-code L-1216C47A \
  --query 'Quota.[QuotaName,Value]' --output text
```

신규 계정 기본값은 **5**입니다. 인스턴스별 vCPU 소요:

| 인스턴스 | vCPU | 물리 코어 | 한도 5에서 |
|---|---|---|---|
| `c8i.xlarge` (Phase A) | **4** | 2 | ✅ 실행 가능 |
| `c8i.2xlarge` | 8 | 4 | ❌ 한도 초과 |
| **`c8i.8xlarge` (Phase B)** | **32** | 16 | ❌ **증설 필수** |

즉 **Phase A는 지금 바로 가능하고, Phase B만 증설이 필요합니다.**

> **⚠ 콘솔에 보인다고 만들 수 있는 것이 아닙니다.** EC2 콘솔의 instance type
> 드롭다운은 vCPU 한도를 반영하지 않고 **리전에서 제공되는 타입을 전부**
> 보여줍니다. `c8i.8xlarge`도 당연히 목록에 뜹니다. 한도는 **Launch를 누르는
> 순간** `VcpuLimitExceeded`로 걸립니다. 목록에 있다 = 실행 가능하다가 아니니,
> 반드시 위 `get-service-quota` 값으로 판단하세요.
>
> 증설 요청은 **무료이고 되돌릴 필요도 없습니다.** 한도가 이미 충분한 것으로
> 밝혀지더라도 손해가 없으므로, 확인에 시간을 쓰기보다 그냥 요청해 두는 편이
> 낫습니다.

```bash
aws service-quotas request-service-quota-increase --region us-east-1 \
  --service-code ec2 --quota-code L-1216C47A --desired-value 64
```

콘솔: **Service Quotas → AWS services → Amazon EC2 → "Running On-Demand
Standard (A, C, D, H, I, M, R, T, Z) instances" → Request increase at
account level**.

64를 권장하는 이유: Phase B(32)에 더해 검증 인스턴스 동시 운용과 재시도 여유를
덮습니다. 이 정도 규모는 자동 승인되는 경우가 많습니다.

**진행 상태 확인:**

```bash
aws service-quotas list-requested-service-quota-change-history-by-quota \
  --region us-east-1 --service-code ec2 --quota-code L-1216C47A \
  --query 'RequestedQuotas[].[Status,DesiredValue]' --output text
```

`CASE_CLOSED` + 값 반영이면 완료입니다. **Step 4로 넘어가기 전에 반드시 한 번
더 확인하세요** — 한도가 모자라면 `run-instances`가 `VcpuLimitExceeded`로
실패합니다.

---

## Step 3 — Phase A: 검증 인스턴스 (`piccard-validate`)

목표: Linux에서 (a) 빌드되고 (b) 테스트가 통과하고 (c) orchestrator가 셀을
실제로 실행한다는 것만 증명한 뒤 AMI를 굽기. toy 모드는 tracked 픽스처만
쓰므로 **실제 데이터셋이 필요 없습니다.**

**인스턴스는 `c8i.xlarge`(4 vCPU / 물리 2코어)입니다.** 현재 vCPU 한도 5 안에
들어가는 가장 큰 크기이고, Phase A는 타이밍을 재지 않으므로 코어 수가 결과에
영향을 주지 않습니다. **SMT도 끄지 않습니다** — 4 vCPU를 전부 빌드에 쓰는 편이
낫습니다(`--cpu-options` 없음).

| 단계 | 내용 | 예상 |
|---|---|---|
| 3.1 | 인스턴스 생성 + 접속 | 10분 |
| 3.2 | 의존성 설치 | 3분 |
| 3.3 | OpenFHE 1.5.0 빌드 | 25~40분 |
| 3.4 | Piccard clone + 빌드 | 12~20분 |
| 3.5 | `ctest` 전체 통과 | ~15분 |
| 3.6 | dry-run + toy 런 | 20~40분 |
| 3.7 | AMI 굽고 terminate | 5분 |

총 약 2~2.5시간 / **~$0.5**.

### 3.1 인스턴스 생성 및 접속

```bash
aws ec2 run-instances --region us-east-1 \
  --image-id resolve:ssm:/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id \
  --instance-type c8i.xlarge \
  --key-name piccard-bench \
  --security-group-ids <SG_ID> \
  --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":30,"VolumeType":"gp3"}}]' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=piccard-validate}]'
```

`<SG_ID>`는 Step 2(b) 스크립트가 마지막에 출력한 보안그룹 ID입니다
(`sg-...`). 잊었으면:

```bash
aws ec2 describe-security-groups --region us-east-1 \
  --filters "Name=group-name,Values=piccard-bench-sg" \
  --query 'SecurityGroups[0].GroupId' --output text
```

Public IP와 인스턴스 ID 확인:

```bash
aws ec2 describe-instances --region us-east-1 \
  --filters "Name=tag:Name,Values=piccard-validate" "Name=instance-state-name,Values=running" \
  --query 'Reservations[].Instances[].[InstanceId,PublicIpAddress,State.Name]' --output text
```

콘솔 사용 시 (**EC2 → Instances → Launch instances**) 요점:

- **Name** `piccard-validate` / **AMI** `Ubuntu Server 24.04 LTS`,
  Architecture **64-bit (x86)** 확인 / **Instance type** `c8i.xlarge`
- **Key pair** `piccard-bench` ("Proceed without a key pair" 금지)
- **Network settings → Edit**: Auto-assign public IP **Enable**, 기존 보안그룹
  `piccard-bench-sg` 선택
- **Storage** **30 GiB gp3** (기본 8 GiB 부족)
- **CPU options는 건드리지 않습니다** (Phase A는 SMT 그대로)

`2/2 checks passed` 후:

```bash
ssh -i ~/.ssh/piccard-bench.pem ubuntu@<PUBLIC_IP>
```

접속 불가 시: Public IP 할당 여부 → 보안그룹의 내 IP 최신 여부 → `.pem` 권한 400.

> `VcpuLimitExceeded`가 나면 vCPU 한도 문제입니다 — Step 2(c). `c8i.xlarge`는
> 4 vCPU라 기본 한도 5에서 통과해야 정상입니다.

### 3.2 의존성 설치

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential cmake git autoconf pkg-config \
    libgmp-dev libssl-dev libomp-dev libgtest-dev \
    python3 python3-venv htop tmux unzip

# ⚠ Python 3.13 이상 필수 — 아래 "Python 버전" 항목 참조
sudo apt-get install -y python3.13 python3.13-venv
mkdir -p ~/bin && ln -sf /usr/bin/python3.13 ~/bin/python3
grep -q 'HOME/bin' ~/.bashrc || echo 'export PATH=$HOME/bin:$PATH' >> ~/.bashrc
export PATH=$HOME/bin:$PATH

nproc                                   # 4
lscpu | grep -E "Model name|^CPU\(s\)"
python3 -c 'import sys,math; print(sys.version.split()[0], hasattr(math,"fma"))'
```

**확인:** `nproc` = 4, Model name에 Xeon 6 계열, Python `3.13.x True`.

- Python 도구는 표준 라이브러리만 사용 — `pip install` 불필요.
- Python3는 필수입니다 (`BUILD_TESTS=ON`에서 없으면 configure가 `FATAL_ERROR`).

> **⚠ Python 버전 — 23시간 런을 통째로 날릴 수 있는 지뢰.**
> `scripts/verify_revision_benchmarks.py`의 `_raw_sample_sd()`가 **`math.fma`**
> 를 씁니다. 이 함수는 **Python 3.13에서 추가**됐고, Ubuntu 24.04의 기본
> `/usr/bin/python3`는 **3.12**라 `AttributeError: module 'math' has no
> attribute 'fma'`로 죽습니다.
>
> `run_revision_benchmarks.py`는 검증기를 `from verify_revision_benchmarks
> import verify_root`로 **같은 인터프리터 안에서** 호출합니다. 따라서 3.12로
> paper 런을 띄우면 **273셀을 전부 돌린 뒤 마지막 verification 단계에서
> 전멸**하고, 런은 재개 불가입니다.
>
> **toy 런은 이 지뢰를 잡지 못합니다.** 측정 count가 전부 1로 투영돼
> `len(values) < 2` 조기 반환에 걸려 `math.fma` 경로에 도달하지 않기 때문입니다.
> 오직 `ctest`의 `VerifyRevisionBenchmarks`(#73)만 잡아냅니다 — Phase A에서
> ctest를 반드시 통과시켜야 하는 이유입니다.
>
> 대응: 위처럼 `python3.13` 설치 + `~/bin/python3` 심링크 + PATH 선점, 그리고
> **CMake configure에 `-DPython3_EXECUTABLE=/usr/bin/python3.13` 명시**
> (CMake는 unversioned `python3`를 먼저 찾으므로 PATH만으로는 비대화형 셸에서
> 새는 경우가 있음), **paper 런도 `/usr/bin/python3.13`로 명시 실행**.

### 3.3 OpenFHE 1.5.0 빌드

```bash
cd ~
git clone --branch v1.5.0 --depth 1 \
    https://github.com/openfheorg/openfhe-development.git
cd openfhe-development
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DBUILD_UNITTESTS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARKS=OFF
cmake --build build -j$(nproc)
sudo cmake --install build

echo '/usr/local/lib' | sudo tee /etc/ld.so.conf.d/openfhe.conf
sudo ldconfig
grep -E "BASE_OPENFHE_VERSION|MATHBACKEND|NATIVE_SIZE" \
    /usr/local/lib/OpenFHE/OpenFHEConfig.cmake
```

**확인:** `1.5.0`, `MATHBACKEND=4`, `NATIVE_SIZE 64`.

> HEXL은 쓰지 않습니다. HEXL의 AVX-512 IFMA 경로는 모듈러스 < 2^50에서만
> 유효한데 이 프로젝트의 `scaling_mod_size`는 40~58비트로 절반 이상이 임계값
> 위이고, 벽시계의 대부분은 SJ16의 GMP-Paillier라 HEXL과 무관합니다.

### 3.4 Piccard clone 및 빌드

빌드에는 실제 Git provenance가 필수입니다 — CMake가 `git rev-parse HEAD`를
실행하고 40자리 commit이 없으면 `FATAL_ERROR`입니다. tarball scp는 configure가
실패합니다.

```bash
cd ~
git clone https://github.com/heewon-chung/piccard_dev.git piccard
cd piccard
git log -1 --format='%H %s'    # Step 1(a) 커밋이 HEAD인지 확인
git status --porcelain          # 비어 있어야 함

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release 2>&1 | tee ~/configure.log
cmake --build build -j$(nproc)

grep -E "Found OpenFHE|Found GMP|Found OpenSSL|Found GTest|Comparison baselines" \
    ~/configure.log
```

**확인 (실제 출력 문자열):**

```
Found OpenFHE: 1.5.0
Found GMP: <lib path>
Found OpenSSL: <version>
Found GTest, building tests
Comparison baselines enabled
```

> `Comparison baselines disabled (need GMP + OpenSSL + OpenFHE)` → BCG12/SJ16
> 미빌드, 비교 실험 불가. Step 3.2로 돌아가세요.
>
> `OpenFHE not found - FHE features disabled` → **provenance 게이트가 통째로
> 건너뛰어집니다** (게이트가 `if(OpenFHE_FOUND)` 안에 있음). 조용한 반쪽
> 빌드이므로 이 grep을 반드시 눈으로 확인하세요.

### 3.5 전체 테스트

```bash
cd ~/piccard/build
ctest --output-on-failure 2>&1 | tee ~/ctest.log
tail -5 ~/ctest.log
```

**확인:** `100% tests passed, 0 tests failed out of 90`.
기준 개수는 `ctest -N`의 마지막 줄(`Total Tests: 90`)을 따르세요.

> **`(Not Run)`은 실패와 다릅니다.** Python 계약 테스트는 configure 시점의
> 인터프리터 **절대경로**가 박혀 있어, 그 경로가 죽으면 `***Not Run`으로
> 빠집니다. `grep _Python3_EXECUTABLE build/CMakeCache.txt`로 확인하고, 죽어
> 있으면 `rm -rf build` 후 완전 재configure.
>
> **`ScriptInventory` 주의.** `scripts/**`에 정본 파일 외의 것이 생기면
> 실패합니다. Python `__pycache__`와 벤치마크 결과물은 **반드시 repo 밖에**
> 두세요 (`--results-root`는 항상 `$HOME` 하위).

### 3.6 dry-run과 toy 런

```bash
cd ~/piccard
unset DRY_RUN      # 부록 A의 지뢰

python3 scripts/run_revision_benchmarks.py --mode=dry-run \
    --build-dir=$HOME/piccard/build --results-root=$HOME/rr-dry \
    --seed=20260729 --threads=16

python3 scripts/run_revision_benchmarks.py --mode=toy \
    --build-dir=$HOME/piccard/build --results-root=$HOME/rr-toy \
    --seed=20260729 --threads=16
```

**확인:**

```
revision dry-run: 275 cells; spawned=0
```
toy 런은 **104셀**을 실제 실행합니다 (측정 count 전부 1, tracked 픽스처 사용).
끝에서 검증·seal을 자동 수행합니다.

### Phase A 통과 체크리스트

- [ ] `OpenFHEConfig.cmake`가 1.5.0 / MATHBACKEND=4 / NATIVE_SIZE 64
- [ ] configure가 provenance `FATAL_ERROR` 없이 완료
- [ ] `Found OpenFHE: 1.5.0` + `Comparison baselines enabled`
- [ ] `ctest` 100% (`Not Run` 0개, 90/90)
- [ ] dry-run **275셀** 통과
- [ ] toy **104셀** 완주 및 seal 생성

**이 체크리스트가 전부 통과해야 Phase B(본 런)로 넘어갑니다.** 하나라도 실패하면
그 원인을 여기서 고치세요 — Phase B는 시간당 4배 비싸고 실패 시 재시작이
불가능합니다. 코드 수정이 필요하면 Mac에서 고쳐 커밋·push한 뒤 이 인스턴스에서
`git pull` → 재빌드 → 재검증하고, 통과한 상태로 AMI를 구우세요.

### 3.7 AMI 굽고 인스턴스 정리

```bash
aws ec2 create-image --region us-east-1 \
  --instance-id <VALIDATE_ID> \
  --name "piccard-openfhe-1.5.0-$(date +%Y%m%d)" \
  --description "Ubuntu 24.04 + OpenFHE 1.5.0 + Piccard deps"

# AMI 상태가 available 이 된 뒤
aws ec2 terminate-instances --region us-east-1 --instance-ids <VALIDATE_ID>
```

잠깐 자리를 비울 때는 terminate 대신 `aws ec2 stop-instances` (중지 시 컴퓨팅
과금 0, EBS만 월 ~$2.4).

---

## Step 4 — Phase B: 측정 인스턴스 (`piccard-bench`)

**여기서부터 시간이 곧 돈이고, 실패하면 처음부터입니다.**
Phase A 체크리스트를 전부 통과한 뒤에만 시작하세요.

### 4.0 선행 조건 확인 (2가지)

```bash
# ① vCPU 한도가 32 이상인가 (Step 2(c)의 증설이 승인됐는가)
aws service-quotas get-service-quota --region us-east-1 \
  --service-code ec2 --quota-code L-1216C47A --query 'Quota.Value' --output text

# ② Phase A AMI가 available 인가
aws ec2 describe-images --region us-east-1 --owners self \
  --filters "Name=name,Values=piccard-openfhe-1.5.0-*" \
  --query 'Images[].[ImageId,State,Name]' --output text
```

**확인:** 한도가 **32 이상**(권장 64), AMI 상태 `available`.
한도가 5 그대로면 `run-instances`가 `VcpuLimitExceeded`로 즉시 실패합니다.

### 4.1 인스턴스 생성 — `c8i.8xlarge`, 물리 16코어

```bash
aws ec2 run-instances --region us-east-1 \
  --image-id <AMI_ID_FROM_3.7> \
  --instance-type c8i.8xlarge \
  --key-name piccard-bench \
  --security-group-ids <SG_ID> \
  --cpu-options "CoreCount=16,ThreadsPerCore=1" \
  --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":100,"VolumeType":"gp3"}}]' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=piccard-bench}]'
```

콘솔에서는 Step 3.1과 동일하되 **AMI 탭 "My AMIs"**, 타입 `c8i.8xlarge`,
CPU options **Core count 16 / Threads per core 1**, 스토리지 **100 GiB gp3**.
IAM instance profile은 불필요합니다 (S3 안 씀).

- vCPU는 하이퍼스레드이므로 32 vCPU = 물리 16코어. `--threads=16`에 정확히
  대응하며, `ThreadsPerCore=1`은 무료이고 OpenFHE 권고(OMP 스레드 ≤ 물리 코어)와
  일치합니다.
- **16 = 무릎점**(gpt-5.6-sol 합의). 그 위로는 직렬 바닥이 지배해 절약시간당
  비용이 3~8배로 뜁니다. 예산 우선이면 8스레드/`c8i.4xlarge`(~31h, ~$23)가 차선.
- **피할 것:** `c8i-flex`/`c7i-flex`(CPU 베이스라인 40%), T 계열(크레딧),
  `c7a`/`c8a`(AMD — CPU options 미지원, SMT 못 끔).

### 4.2 측정 환경 고정

```bash
sudo systemctl disable --now unattended-upgrades snapd.service snapd.socket
nproc                                   # 16이어야 함

# 주파수 로거 (논문 보고용, 부록 B)
( while true; do
    printf '%s %s\n' "$(date -Is)" "$(grep 'cpu MHz' /proc/cpuinfo | head -1)"
    sleep 300
  done ) > ~/cpu-mhz.log 2>&1 &
```

측정 중 `apt`가 깨어나면 설명 불가능한 타이밍 outlier가 됩니다.
가상화 인스턴스에서는 클럭을 고정할 수 없으므로(P-state 제어는 `.metal` 전용)
실제 지속 주파수를 로그로 남겨 논문에 보고합니다.

### 4.3 재빌드 (필수) 및 ctest 재확인

AMI의 OpenFHE는 재사용해도 되지만 **Piccard는 측정 인스턴스에서 다시 빌드해야
합니다** — `PICCARD_CONFIGURED_BUILD_ID`가 측정 머신과 1:1로 대응해야 하기
때문입니다.

```bash
cd ~/piccard
git fetch origin && git checkout main && git pull
git log -1 --format='%H %s'     # Step 1(a) 커밋 포함 확인
git status --porcelain          # 비어 있어야 함
export PATH=$HOME/bin:$PATH          # python3 = 3.13 (Step 3.2 참조)
rm -rf build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
      -DPython3_EXECUTABLE=/usr/bin/python3.13
cmake --build build -j$(nproc)
cd build && ctest --output-on-failure
```

**확인:** `100% tests passed, 0 tests failed out of 91`, 그리고

```bash
grep _Python3_EXECUTABLE build/CMakeCache.txt    # /usr/bin/python3.13 이어야 함
```

`/usr/bin/python3`(3.12)가 잡혔다면 `VerifyRevisionBenchmarks`(#73)가
`math.fma` `AttributeError`로 실패합니다 — Step 3.2의 경고 참조.
tmux/`ssh host 'cmd'` 같은 **비대화형 셸은 `.bashrc`를 읽지 않아** PATH 선점이
새므로, `-DPython3_EXECUTABLE`을 명시하는 편이 안전합니다.

### 4.4 데이터셋 배치

Mac에서:

```bash
scp -i ~/.ssh/piccard-bench.pem /tmp/piccard-processed.tar.gz ubuntu@<IP>:~/
```

인스턴스에서:

```bash
tar xzf ~/piccard-processed.tar.gz -C ~/piccard/datasets/data
ls ~/piccard/datasets/data/processed
```

**확인:** `dblp_acm_u65536_paper`, `enron_u65536`, `enron_u1048576` 3개 디렉터리.

### 4.5 환경 변수 — 빠뜨리면 나중에 검증이 깨집니다

```bash
echo 'export PICCARD_OPENFHE_VERSION=1.5.0' >> ~/.bashrc
export PICCARD_OPENFHE_VERSION=1.5.0
unset DRY_RUN
```

**`PICCARD_OPENFHE_VERSION`**은 run manifest의 `tools.openfhe`에 기록됩니다.
미설정 시 `"not-probed"`가 기록됩니다. CMake의 동명 compile definition과는
연결되어 있지 않으므로 손으로 export해야 하며, 새 SSH 세션에서도 살아 있도록
`.bashrc`에도 넣습니다.

> **비대칭 함정.** 검증기는 tools 딕셔너리를 **재계산해 비교**합니다
> (`compiler/CMake/OpenFHE tool metadata changed`). 런 때 설정하고 post-seal
> 재검증 때 빠뜨리면 **봉인된 런을 재검증할 수 없습니다.** 같은 딕셔너리에
> platform, `c++ --version`, `cmake --version`, `cmake_cache_sha256`도 들어가므로
> post-seal 검증은 **같은 머신, 같은 컴파일러, `build/CMakeCache.txt` 무변경**
> 상태에서 해야 합니다.

**`DRY_RUN`**: 값이 `1`이면 flooding 셀이 조용히 no-op이 됩니다.

### 4.6 Paper 런 실행

반드시 `tmux` 안에서 실행하세요. SSH가 끊겨도 런이 살아남습니다.

```bash
tmux new -s bench
cd ~/piccard
export PATH=$HOME/bin:$PATH
export PICCARD_OPENFHE_VERSION=1.5.0
unset DRY_RUN

/usr/bin/python3.13 scripts/run_revision_benchmarks.py \
    --mode=paper \
    --authorize-paper-run \
    --build-dir=$HOME/piccard/build \
    --results-root=$HOME/piccard-results-$(date +%Y%m%d) \
    --seed=20260729 \
    --threads=16 \
    --paper-dblp-manifest=$HOME/piccard/datasets/data/processed/dblp_acm_u65536_paper/dataset.manifest.tsv \
    --paper-enron-u65536-manifest=$HOME/piccard/datasets/data/processed/enron_u65536/dataset.manifest.tsv \
    --paper-enron-u1048576-manifest=$HOME/piccard/datasets/data/processed/enron_u1048576/dataset.manifest.tsv \
    2>&1 | tee ~/paper-run.log
```

`Ctrl-b d`로 detach, `tmux attach -t bench`로 재접속.

**경로·인자 규칙 (어기면 즉시 exit 2):**

| 인자 | 규칙 |
|---|---|
| `--build-dir` | 절대경로, 존재, 심볼릭 링크 불가 |
| `--results-root` | 절대경로, **비존재**, **Git worktree 밖** |
| `--seed` | **20260729** (프로즌 게이트) |
| `--threads` | **16** |

`export OMP_NUM_THREADS=...`는 불필요합니다 — orchestrator가 자식 프로세스마다
직접 설정합니다.

**실행 중 이 인스턴스에서 다른 작업을 하지 마세요.** 타이밍 셀은 코어 경합이
없음을 가정합니다. 모니터링은 두 번째 tmux 창에서 읽기만 하세요:

```bash
tail -f ~/paper-run.log
watch -n 300 'ls ~/piccard-results-*/cells | wc -l'
```

**페이즈별 셀 분포 (진행 상황 가늠용):**

```
preflight(0) → synthetic(101) → comparison(27) → real-fixtures(12)
             → dynamic-deletion(35) → threshold(100) → verification → seal
```

`preflight`는 셀 0개짜리 빈 마커라 사전 점검이 없습니다. Step 1·3을 먼저 끝내야
하는 이유입니다.

### 4.7 중단된 런 재개 — `--resume`

런이 도중에 죽었을 때, 같은 `--results-root`에 `--resume`을 붙여 다시 실행하면
**독립적으로 완료를 재확인할 수 있는 셀만 남기고 나머지를 이어서 실행합니다.**
나머지 인자는 최초 런과 **한 글자도 다르면 안 됩니다.**

```bash
tmux attach -t bench    # 또는 tmux new -s bench

/usr/bin/python3.13 scripts/run_revision_benchmarks.py \
    --mode=paper \
    --authorize-paper-run \
    --resume \
    --build-dir=$HOME/piccard/build \
    --results-root=$HOME/piccard-results-<최초 런과 같은 날짜> \
    --seed=20260729 \
    --threads=16 \
    --paper-dblp-manifest=... --paper-enron-u65536-manifest=... \
    --paper-enron-u1048576-manifest=... \
    2>&1 | tee -a ~/paper-run.log
```

시작하면 한 줄로 무엇을 이어받았는지 알려줍니다:

```
revision resume: retained 170/275 cells; continuing from phase dynamic-deletion;
superseded evidence in superseded/attempt-1
```

**resume이 거부하는 경우 (모두 `exit 2`, 결과 루트는 손대지 않음):**

| 거부 사유 | 이유 |
|---|---|
| `source`/`scripts`/`tools`/`binaries` 중 하나라도 변함 | **가장 중요.** 아래 참조 |
| `--results-root`가 없거나 `run.json`이 없음 | 이어받을 증거가 없음 |
| 이미 `seal.json`이 있음 | 봉인된 루트는 terminal |
| 이미 `verification/receipt.json`이 있음 | 실행 단계를 이미 지남 |
| `run.json`의 `state`가 `COMPLETED` | 끝난 런 |
| `--mode`/`--seed`/`--threads`/`--build-dir`/matrix SHA/cell 목록이 다름 | 다른 런 |
| `planned_argv.jsonl`이 지금 만들어지는 plan과 다름 | 계획이 바뀜 |
| `--mode=dry-run` | dry plan은 정적 투영이라 이어받을 실행이 없음 |

> **⚠ 코드를 고치고 다시 빌드한 뒤에는 resume 할 수 없습니다.**
> `verify_revision_benchmarks.py`는 검증 시점에 `git rev-parse HEAD` +
> `git status`, 스크립트 5개의 SHA-256, `c++`/`cmake` 버전과
> `CMakeCache.txt` 해시, **그리고 producer 바이너리 16개의 SHA-256을 전부 다시
> 계산해서** `run.json`이 기록한 값과 **완전히 같은지** 비교합니다
> (`_check_source_and_tools`). 즉 버그를 고치고 재빌드하면 그 결과 루트는
> resume 여부와 무관하게 **영원히 검증에 실패합니다.** 그래서 runner가 먼저
> 거부합니다 — 21시간을 더 쓴 뒤 검증에서 깨지는 것보다 즉시 거부가 낫습니다.
>
> 이것은 편의를 포기한 게 아니라 **논문 측정의 provenance를 지키는 것**입니다.
> 셀 170개가 A 바이너리에서, 105개가 B 바이너리에서 나왔다면 그건 하나의
> 측정이 아닙니다. 코드 수정이 필요한 실패는 **처음부터 다시** 돌려야 합니다.
>
> resume이 실제로 구해주는 실패는 **코드와 무관한 중단**입니다: OOM, 디스크
> 가득 참, SSH/tmux 유실, spot 회수, 조작 실수로 인한 `^C`, 일시적 타임아웃.
> 지금까지 3번의 실패 중 attempt 1·2·3은 모두 코드 수정이 필요했으므로
> resume으로 구제되지 않았을 것입니다. 4회차부터가 대상입니다.

**완료 판정은 receipt를 믿지 않고 다시 계산합니다.** 셀 하나가 "완료"로
인정되려면 receipt의 schema/argv/timeout/expected_rows가 plan과 일치하고,
`stdout.log`·`stderr.log`의 SHA-256이 디스크와 일치하고, `artifact_inventory`가
셀 디렉터리 실제 내용과 완전히 같고, 이벤트가 정확히 START/END 한 쌍에
`exit_code=0`이어야 합니다. 하나라도 어긋나면 그 셀은 **다시 실행**됩니다.
셀당 재확인 비용은 밀리초, 재실행 비용은 분~시간이라 항상 재확인이 이득입니다.

**FAILED 셀은 건너뛰지 않고 반드시 다시 실행합니다.** 그 셀의 디렉터리는
`raw/`·부분 CSV까지 통째로 `superseded/attempt-N/cells/<slug>/`로 옮겨진 뒤
**빈 디렉터리에서 새로 시작**합니다. 남은 부분 산출물은 `artifact_inventory`
동등성과 family allowlist를 깨뜨리고, flooding wrapper는 `payload/`가 없어야만
동작하기 때문입니다.

**증거는 지워지지 않고 이관됩니다.** resume은 `events.jsonl`을 살아남은 셀의
쌍만 남겨 1부터 다시 번호를 매기고(검증이 전역 연속 시퀀스를 요구),
`phases.jsonl`을 완료된 페이즈의 prefix까지 잘라내며(검증이 정확한 상태기계를
요구), 잘려나간 레코드와 셀 디렉터리는 전부
`superseded/attempt-N/` 아래에 보존합니다. 번호가 바뀐 셀의 receipt는
`start_event_sequence`/`end_event_sequence`가 함께 갱신됩니다.

**resume은 기록되는 행위입니다.** `run.json`의 `resume` 블록, 최상위
`resume.jsonl`, 그리고 최종 `seal.json`의 `resumed`/`resume_count`/
`resume_attempts`/`provenance_sha256`에 남습니다. 봉인된 산출물만 봐도 이 런이
몇 번 재개됐고 어느 페이즈에서 이어졌는지 알 수 있습니다.
`provenance_sha256`은 모든 셀이 나온 **단 하나의** 빌드를 고정합니다.

---

## Step 5 — 검증 및 결과 회수

**검증과 seal은 런 종료 시 자동 수행됩니다.** 별도 명령이 필요 없습니다.

읽기 전용 재확인이 필요할 때만 (같은 머신·같은 컴파일러·`CMakeCache.txt`
무변경 상태에서, 환경변수 포함):

```bash
export PICCARD_OPENFHE_VERSION=1.5.0        # Step 4.5의 비대칭 함정
python3 scripts/verify_revision_benchmarks.py \
    $HOME/piccard-results-<날짜> --mode=post-seal
```

회수:

```bash
tar czf ~/piccard-results.tar.gz -C ~ piccard-results-<날짜> cpu-mhz.log paper-run.log
```

Mac에서:

```bash
scp -i ~/.ssh/piccard-bench.pem ubuntu@<IP>:~/piccard-results.tar.gz ~/Downloads/
```

수십 MB 수준이라 월 100 GB 무료 egress 한도 안입니다.

> **논문 표 생성 도구는 현재 없습니다.** `summarize_results.py`는 삭제됐고
> 대체물이 없습니다. `summarize_real_datasets.py`는 대체재가 아니라 matrix
> producer(real-summary 3셀)입니다. 봉인된 결과 → LaTeX 표 단계는 별도로
> 마련해야 합니다. **결과 아카이브를 Mac으로 회수하기 전에는 인스턴스를 지우지
> 마세요.**

---

## Step 6 — 정리 (당일 안에)

> **종료 전 확인 세 가지.** (1) 결과 아카이브를 Mac으로 회수했고 양쪽 크기가
> 일치하는지, (2) 종료하려는 인스턴스 ID가 **본인이 띄운 그것**인지
> (`aws ec2 describe-instances`로 Name 태그를 확인 — 이 계정에는 다른 캠페인의
> 인스턴스가 동시에 떠 있을 수 있고, 남의 실행을 종료하면 복구할 수 없습니다),
> (3) 그 인스턴스에서 아직 벤치마크가 돌고 있지 않은지
> (`ps -eo args | grep bench_`). 셋 중 하나라도 확실하지 않으면 종료하지 마십시오.

```bash
aws ec2 terminate-instances --region us-east-1 --instance-ids <BENCH_ID>

# 잔존 확인 — terminate 후에도 EBS 볼륨이 남아 과금될 수 있습니다
aws ec2 describe-instances --region us-east-1 \
    --query 'Reservations[].Instances[].[InstanceId,State.Name,InstanceType]' --output table
aws ec2 describe-volumes --region us-east-1 \
    --query 'Volumes[?State==`available`].[VolumeId,Size]' --output table
```

두 쿼리 모두 비어 있어야 합니다. AMI/snapshot도 불필요해지면 삭제
(**EC2 → AMIs → Deregister → Snapshots → Delete**).
**Elastic IP는 할당하지 마세요** — 인스턴스에 미연결 상태로 시간당 과금됩니다.

---

## 부록 A — 문제 해결

**구조적 제약: 재시작 불가.** 셀 하나라도 exit ≠ 0이면 런 전체가 중단됩니다.
`--resume` / `--only` / `--from-phase` / checkpoint / skip-completed는 **존재하지
않습니다.** `--results-root`는 이미 존재하면 거부하므로 재시도는 항상 새 경로에
처음부터입니다.

| 증상 | 원인과 조치 |
|---|---|
| `build-dir must be an absolute path` | `--build-dir`/`--results-root`/`--matrix`는 절대경로 |
| `results-root must be a fresh absent directory` | 재시도마다 새 경로 |
| `--results-root must be outside the Git worktree` | flooding 경로가 강제. `$HOME/piccard-results-*` 권장 |
| macOS에서 `/tmp` results-root 거부 | `/tmp`가 심볼릭 링크. `/private/tmp` 또는 `$HOME` 하위 (Linux는 무관) |
| `--seed=N contradicts frozen successor seed 20260729` | seed는 20260729 고정 |
| `--threads=N contradicts frozen successor threads 2` | **Step 1(a) 커밋이 인스턴스에 pull되지 않음.** `git log -1` 확인 후 `git pull` |
| `paper manifest <variant> seed does not match root seed` | 데이터셋 생성 시드가 20260729가 아님. Step 1(b) 재생성 |
| `paper manifest dblp_acm_u65536 DBLP count fields mismatch` | DBLP를 `--pairs=10000`으로 재생성하지 않음. Step 1(b) |
| `invalid choice: 'dblp_acm'` | 서브커맨드는 `dblp-acm`(하이픈) |
| `output directory already exists` | `prepare_real_datasets.py`에 `--overwrite` 없음. 기존 디렉터리를 먼저 옮길 것 |
| `executable revision runs require a tracked-clean source tree` | 수정된 tracked 파일 존재 (untracked는 무관). `git status --short` |
| `paper mode requires the explicit --authorize-paper-run token` | 토큰 누락 |
| `Evidence builds require a full Git source commit` | Git clone이 아닌 곳에서 빌드. tarball scp 금지 |
| `producer failed for <cell> with exit code -124` | per-cell 하드 타임아웃. **Step 1(a) 커밋(`long` 클래스 64,800 s)이 인스턴스에 없음.** 런 전체 중단, 재개 불가 |
| `missing threshold legacy calibration ... natural depth 21` | **Step 1(a) 커밋(k=256 NO_SPAWN 강등)이 인스턴스에 없음** |
| `compiler/CMake/OpenFHE tool metadata changed` | 검증 환경이 런 환경과 다름. 대개 `PICCARD_OPENFHE_VERSION` 누락, 다른 머신/컴파일러, `CMakeCache.txt` 변경. Step 4.5 |
| flooding 셀이 아무것도 측정하지 않음 | `DRY_RUN=1`이 export됨. `unset DRY_RUN` |
| `Could NOT find OpenSSL (missing: Crypto)` | `sudo apt-get install -y libssl-dev` |
| 링커가 `libOPENFHEcore.so`를 못 찾음 | `echo '/usr/local/lib' \| sudo tee /etc/ld.so.conf.d/openfhe.conf && sudo ldconfig` |
| 테스트가 무더기로 `***Not Run` | CMake cache의 Python 절대경로가 죽음. `rm -rf build` 후 완전 재configure |
| `AttributeError: module 'math' has no attribute 'fma'` | **인터프리터가 Python 3.12.** `math.fma`는 3.13 신규. `/usr/bin/python3.13`으로 실행하고 CMake도 `-DPython3_EXECUTABLE`로 고정. Step 3.2 경고 — **paper 런에서는 273셀을 다 돌린 뒤 검증 단계에서 터집니다** |
| `ScriptInventory` 실패 | `scripts/` 아래 비정본 파일(`__pycache__`, 결과물, `.DS_Store`). 결과는 repo 밖에 |
| `VcpuLimitExceeded` | vCPU 한도 부족. Step 2(c) — `c8i.xlarge`=4, `c8i.2xlarge`=8, `c8i.8xlarge`=32 vCPU |
| `InvalidGroup.NotFound` / SG 지정 실패 | `--security-groups`(이름) 대신 `--security-group-ids sg-...` 사용 |

---

## 부록 B — 논문에 기록할 사항

- 하드웨어: AWS **`c8i.8xlarge`** (Intel Xeon 6 / Granite Rapids),
  **`ThreadsPerCore=1`로 SMT 비활성화, 물리 16코어**
- 소프트웨어: Ubuntu 24.04, GCC, **OpenFHE 1.5.0 (Intel HEXL 미사용)**,
  `MATHBACKEND=4`, `NATIVE_SIZE=64`
- **스레드 정책 (3층)** — 이 계층 구조를 그대로 기술할 것:

  | 대상 | 실제 스레드 |
  |---|---|
  | 일반 셀 (Piccard + baseline 타이밍 포함) | **16** (`OMP_NUM_THREADS`, `OMP_DYNAMIC=FALSE`) |
  | flooding 3셀 (노이즈 측정) | 2 (동결 계약, argv 리터럴) |
  | `sj16::fit=per_element` (calibration) | 2 (자체 핀) |

- **실험 matrix: 275셀 = 273 RUN + 2 NO_SPAWN.** NO_SPAWN 2셀은
  `sj16::u=262144`, `sj16::u=1048576`이며 비용 사유로 `EXTRAPOLATED` 처리됩니다.
- **threshold k=256은 측정에 포함됩니다.** k=256 → `feature_dim` 16384 →
  Paterson–Stockmeyer 깊이 **21**, provisioned depth 22, ring_dim 16384
  (calibrated N=32768), `scaling_mod_size` 45. 이를 위해
  `noise_calibration.inc`에 `(Threshold, STD128, 16384, depth 21)` 측정 행이
  추가되었고, `bench_threshold.cpp`의 "depth>21 at STD128 거부" 보수적 가드가
  **이 측정 구성에 한해서만** 완화되었습니다(그 외 미측정 depth>21 구성은 여전히
  거부). 논문에는 이 행이 **추가 측정 프로브에서 온 것**임과 가드 완화 범위를
  명시하세요.
- **sqrt(Piccard⁺) 스윕이 확장되었습니다:** `sqrt_comparison` 32셀이 m축뿐 아니라
  **k축(`timing_k` = 16/32/64/256/512), n축(`timing_n` = 100/10000/100000),
  (k,m) 조합(`timing_km`/`ciphertext_km`)**까지 덮습니다. 기존 m축 20셀의 argv는
  바이트 동일하게 유지됩니다.
- **검증기의 표준편차 비교는 상대 1e-9 / 절대 1e-12 허용 밴드를 씁니다.**
  부동소수점 reduction 순서 차이로 인한 비결정성을 흡수하기 위한 것으로,
  재현성 주장 시 이 허용오차를 명시하세요.
- 노이즈 캘리브레이션 테이블(`include/util/noise_calibration.inc`)은
  **macOS arm64 / OpenFHE 1.5.0**에서 측정되었고, 본 측정은
  **Linux x86_64 / 동일 OpenFHE 버전**에서 수행되었습니다. 테이블은 사실상
  동결 상태(raw CSV 삭제, 재생성 경로 없음)이므로 재생성을 시도하지 마세요.
- root seed **20260729** (증거 사슬 전반에 하드 게이트로 짜여 있음)
- 가상화 인스턴스라 CPU 주파수를 고정할 수 없습니다 — `~/cpu-mhz.log`의 관측
  지속 주파수를 보고하세요.

---

## 부록 C — 비용

us-east-1 on-demand, AWS Price List API 기준.

| 항목 | 단가 | 시간 | 비용 |
|---|---|---|---|
| **Phase A** `c8i.xlarge` | $0.1874/h | ~2.5 h | ~$0.47 |
| EBS 30 GiB gp3 | $0.08/GB-월 | 1일 | ~$0.08 |
| **Phase B** `c8i.8xlarge` 재빌드+준비 | $1.4994/h | ~1 h | ~$1.50 |
| Paper 본 런 | $1.4994/h | **~23.4 h** | **~$35.1** |
| 검증 + 회수 | $1.4994/h | ~0.5 h | ~$0.75 |
| EBS 100 GiB gp3 | $0.08/GB-월 | 2일 | ~$0.55 |
| **총합** | | | **~$39** |

예산 대안: 8스레드 / `c8i.4xlarge`로 ~31 h, 본 런 ~$23 — $12 아끼고 ~8시간 더
걸립니다.

절감 효과가 큰 순서: ① Step 1·3을 빠짐없이 끝내기 (실패한 23시간 런이 $35)
② 자리 비울 때 `stop` (단, 본 런 중에는 불가 — 재개 없음) ③ 종료 후 EBS 잔존 확인.

**소요시간 ~23.4시간은 투영값입니다** (밴드 16~34 h). 측정 근거 상수는 repo가
기록한 Paillier 17.892 ms/enc 하나로 총량의 약 88%를 결정하며, 16코어에서
GMP/OpenMP가 실제로 효율 0.9를 내는지가 가장 큰 불확실성입니다.

---

## 부록 D — 미결 사항

1. ~~**resume 기능 부재**~~ — **해결됨** (Step 4.7). `--resume`이 셀 단위로
   재개합니다. 다만 **범위가 제한적이라는 점이 남은 리스크입니다**: 검증이
   source/scripts/tools/binaries를 런 시점과 완전히 동일하게 요구하므로
   **코드를 고쳐 재빌드한 뒤에는 resume 할 수 없습니다.** 지금까지의 실패 3건은
   모두 코드 수정이 필요했으므로 resume으로는 구제되지 않았을 것입니다. resume이
   덮는 것은 OOM·디스크·SSH 유실·spot 회수·조작 실수 같은 **코드와 무관한
   중단**입니다.
   **미결 판단 사항:** 빌드가 바뀐 재개를 (per-cell build provenance를 기록하고
   seal에 "N개 빌드에 걸친 런"임을 명시하는 방식으로) 허용할지 여부. 허용하면
   attempt 3 같은 실패에서 21시간을 건질 수 있지만, "모든 셀을 낳은 바이너리를
   검증 시점에 다시 해시할 수 있다"는 현재의 증거 강도를 잃습니다. 현재 구현은
   **허용하지 않는 쪽**을 택했습니다.
2. **표 생성 도구 부재** — 봉인된 결과에서 논문 표를 뽑는 경로가 없습니다 (Step 5).
3. **CLAUDE.md 수치 갱신 필요** — "110 registered tests"(실제 90),
   `--build-dir=build` 예시(절대경로 필수), "263 cells"(실제 275),
   "verification checks the exact OpenFHE version"(실제로는 자기일관성 검사이며
   `"not-probed"`도 통과).

---

## 이 가이드의 근거

- 계획·설계는 gpt-5.6-sol (high)와 3라운드 교차 검토로 합의, 최종 APPROVE.
  스레드 16, 인스턴스 선택, k=256 제외, `long` 타임아웃 방식이 그 산물입니다.
- 코드 변경은 5단계 파이프라인으로 구현·검증 완료
  (`docs/superpowers/plans/2026-08-16-aws-prep-section1-implementation.md`).
  **현재 워킹 트리에 있고 아직 커밋되지 않았습니다 — Step 1(a).**
- 로컬 Mac에서 실행으로 확인한 수치: dry-run **275 cells; spawned=0**,
  matrix 275셀(초기 검증 시점 270 RUN + 5 NO_SPAWN; 이후 k=256 활성화로 273 RUN + 2 NO_SPAWN), `long` 타임아웃 10셀, toy 골든 목록
  104셀, `ctest -N` 90개, `planned_processes` 270,
  matrix SHA-256 `46b318c7…0d37ef9d`.
- **Linux 런타임은 아직 검증되지 않았습니다.** Phase A(Step 3)가 최초 검증입니다.
</content>
