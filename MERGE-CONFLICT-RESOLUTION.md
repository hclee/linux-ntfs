# 포팅 중 충돌 및 중복 처리 기록

## 작업 범위

- 기준 커밋: `remotes/nj/ntfs-next` (`d7fb9077b24e2e01df437b0b7f01d25c98301409`)
- 대상 브랜치: `port/4kn-symlink-loop-20261008`
- 소스 경로: `remotes/nj/ntfs-next..port/4kn`, `fix/symlink-loop`의
  `021f114ff268f9e7b2d6334ea35824985f1021d2` 및
  `c519c144e7fb49c8e79b307871efe65eb4aa32cb`
- 외부 커밋: `8f03e90708d36c1442ddea69f7b49b20130b9a72`
  (`fs/ntfs/attrib.c`, `fs/ntfs/inode.c` → `attrib.c`, `inode.c`)

## 충돌 처리

### `fb5f9f7f40593158d4b33f5fcac010bef8596763`

- 파일/구간: `Makefile`의 `ccflags` 선언부.
- 원인: 소스 커밋은 외부 모듈 빌드를 위해
  `ccflags-$(CONFIG_NTFS_FS_WOF_COMPRESSION)`를 추가했지만, 기준 트리에는
  같은 WOF 플래그가 이미 존재했다. 동시에 기준 트리는 POSIX ACL 플래그를
  `CONFIG_FS_POSIX_ACL` 조건부로 설정하고 있었고 소스 쪽은 `ccflags-y`를
  사용해 문맥이 달랐다.
- 양쪽 의도: 소스는 WOF 압축 코드가 외부 모듈 빌드에서도 올바른 매크로로
  컴파일되게 하려는 것이고, 기준 트리는 기존 POSIX ACL 호환 분기를
  보존하려는 것이다.
- 최종 선택: 기준 트리의 POSIX ACL 조건부 선언과 이미 존재하는 WOF 선언을
  유지했다. 따라서 소스 변경의 동작은 이미 반영되어 있어 결과 커밋
  `f421631b7ecb`는 원본 메시지와 저자를 보존한 빈 매핑 커밋으로 만들었다.

### `44916013cf628a1cd8a164f2f60afd0c0c627f83`

- 파일/구간: `mft.c`의 `ntfs_mft_record_alloc()` 지역 변수 선언부와
  `ntfs_mft_record_free()`의 비트맵 해제 직후.
- 원인: 소스 커밋의 동적 MFT tail reservation 구현은 기준 트리에 이미
  다른 커밋 해시로 반영되어 있었다. 충돌한 두 줄은 기준 트리에 추가된
  `nr_new_mft_records` 회계와 `ntfs_inc_free_mft_records()` 호출이었다.
- 양쪽 의도: 소스는 MFT 메타데이터용 동적 reserve를 유지하고, 기준 트리는
  그 동작에 더해 새로 초기화된 MFT 레코드 수를 free-record 회계에 반영한다.
- 최종 선택: 기준 쪽의 회계 코드를 유지했다. `attrib.c`, `volume.h` 및
  나머지 `mft.c` 변경은 기준 트리에 이미 존재하는 동적 reserve 구현과
  일치했으므로 소스 변경을 중복 적용하지 않았다. 결과 커밋
  `fa665eb7a4d9`는 원본 메시지와 저자를 보존한 빈 매핑 커밋이다.

### `fe0e0bbab9dfbb27960518ab2f5db576b375f8db`

- 파일/구간: `attrib.c`의 ATTRIBUTE_LIST mapping-pairs 재시도 경로와
  `ntfs_attr_expand_locked()` 호출부, `attrlist.c`의
  `ntfs_attrlist_repack()` 및 `ntfs_attrlist_update_locked()` 호출부.
- 원인: 소스 커밋의 재패킹 구현은 기준 트리에 이미 반영되어 있었고, 기준
  트리는 이후 runlist 잠금 재진입을 피하기 위한 `locked_ni` 인자와
  `*_locked()` API까지 포함하고 있었다. 소스 쪽의 잠금 없는 호출을
  그대로 선택하면 기준 트리의 잠금 안전성을 되돌리게 된다.
- 양쪽 의도: 소스는 `$MFT:$ATTRIBUTE_LIST`를 연속 run으로 재배치하고
  오류를 전파하는 것이며, 기준 쪽은 같은 동작을 유지하면서 이미 추가된
  runlist 잠금 규칙까지 보존하는 것이다.
- 최종 선택: 기준 쪽의 `locked_ni` 기반 구현을 유지했다. `inode.c`의
  동기 BIO 오류 처리도 기준 트리에 이미 포함되어 별도 변경이 없었다.
  결과 커밋 `93cf0587b769`는 원본 메시지와 저자를 보존한 빈 매핑 커밋이다.

## 기준 트리에 이미 있던 소스 커밋

위 세 충돌 커밋을 포함해 `fb5f9f7f4059`부터
`5eed35ec31d8`까지의 첫 18개 4Kn 커밋은 기준 트리의 동등한 변경
(`d181c220c4e5`, `990fe712826f`, `6607515d300d`, `a5fdd2333b88`,
`e305407810bd`, `a11c4debc60c`, `535129e85376`, `eb490ca6aa95`,
`8cf4d148051b`, `533c48a95700`, `c2600004292b`, `f1064677ee71`,
`e0c195d1d9f0`, `bdc7df7edcd3`, `dff3cdcfc8cc`, `f6876ed95bde`,
`87bea1a83b02`, `d7fb9077b24e`)로 이미 존재했다. 소스 커밋을 건너뛰지
않고 각 원본 메시지/저자/트레일러를 가진 빈 결과 커밋을 순서대로 만들었다.
19번째 `4d2dbd534d24...`부터는 실제 4Kn 변경을 원래 순서로
cherry-pick했다.

## 외부 커밋 `8f03e90708d36c1442ddea69f7b49b20130b9a72`

원본의 `fs/ntfs/attrib.c` 변경은 앞서 적용한
`c519c144e7fb49c8e79b307871efe65eb4aa32cb`와 동일한
`compressed_size` 검증 변경이다. 따라서 `attrib.c` hunk를 다시 적용하지
않았다. 원본의 `fs/ntfs/inode.c` 변경은 out-of-tree `inode.c`에 수동으로
매핑했다. `ntfs_read_locked_inode()`와
`ntfs_read_locked_attr_inode()`에서 `lowest_vcn` 검사를
`compressed_size`를 읽기 전에 수행하도록 옮겨, continuation extent의
누락된 `compressed_size`를 읽지 않으면서 첫 extent만 허용하는 원래
의미를 보존했다. 외부 커밋의 `Fixes:` 및 두 `Signed-off-by:`를 포함한
전체 메시지로 별도 결과 커밋을 만들었다.
