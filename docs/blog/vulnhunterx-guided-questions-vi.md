# VulnHunterX: LLM-powered Automated Vulnerability Hunting

Các công cụ SAST như CodeQL, Semgrep hay OpenGrep được thiết kế để "thà báo nhầm còn hơn bỏ sót". Hệ quả là chi phí lớn nhất khi vận hành SAST trong thực tế không nằm ở thời gian phân tích, mà nằm ở việc một kỹ sư phải ngồi đọc cảnh báo thứ 212 trên tổng số 400 và tự hỏi lần thứ tư trong ngày: liệu hàm `escapeshellarg()` cách đó hai stack frame có thực sự vô hiệu hóa được sink hay không.

---

**1. Giới thiệu**

Mọi engine SAST hiện đại đều hoạt động theo nguyên tắc xấp xỉ thừa (over-approximation): đánh dấu/cảnh báo *mọi* điểm trong chương trình mà kẻ tấn công *có thể* chạm tới, bởi vì nếu lựa chọn — im lặng bỏ qua — đồng nghĩa với nguy cơ để lọt lỗ hổng thật. Đây là một quyết định thiết kế đúng, nhưng nó đẩy toàn bộ chi phí sang phía con người.

Dữ liệu cụ thể từ các bộ dữ liệu có đối chứng: với OWASP BenchmarkPython, nếu coi mọi cảnh báo SAST là thật thì precision chỉ đạt **37,7%** — nghĩa là gần hai phần ba khối lượng triage là công vô ích. Với bộ dữ liệu Juliet C/C++ 1.3.1, tỉ lệ này là **50%**. Để giảm cảnh báo giả, cách tiếp cận phổ biến hiện nay là đưa cảnh báo cho LLM và hỏi "đây có phải lỗ hổng thật không?". LLM thông thường sẽ trả về một câu trả lời có vẻ rất tự tin nhưng về bản chất lại khá may rủi, vì mô hình thường không có đủ dữ kiện để trả lời — và quan trọng hơn, không ai kiểm chứng được nó đã suy luận dựa trên cái gì.

Bài viết này mô tả cách VulnHunterX giải bài toán đó: không phải bằng một mô hình mạnh hơn, mà bằng cách **bắt mô hình trả lời một bộ câu hỏi có cấu trúc, gắn với từng loại lỗi cụ thể, trước khi được phép đưa ra kết luận** — hiện thực hóa và cải tiến phương pháp luận *Vulnhalla* đã được trình bày bởi Simcha tại BlackHat EU tháng 12/2025.

---

**2. Vì sao thẩm định tính đúng đắn của cảnh báo lại khó đến vậy**

**2.1. Một cảnh báo SAST là một mảnh ghép thiếu ngữ cảnh**

Thông tin mà SAST trả về thường chỉ gồm: Mã lỗi (rule id), đường dẫn file, số dòng, mức độ nghiêm trọng, một đoạn thông tin ngắn, và nếu may mắn thì một chuỗi các bước dataflow từ source tới sink. Trong khi đó, để kết luận một cảnh báo là thật, người phân tích cần biết:

- **Định nghĩa của hàm tại dòng mã bị cảnh báo** — dòng đó nằm trong nhánh nào, có được bảo vệ bởi điều kiện nào không (control flow).
- **Các lời gọi tới hàm đó (callers)** — biến đầu vào thực sự đến từ đâu, có bao nhiêu luồng thực thi, luồng nào có thể bị điều khiển bởi kẻ tấn công (attacker).
- **Các hàm được gọi (callees)** — sink thật nằm sâu hai ba lớp, và một hàm helper tên vô hại hoàn toàn có thể là nơi thực thi lệnh.
- **Định nghĩa kiểu dữ liệu** — struct, class, typedef, enum. Kích thước một buffer nằm trong định nghĩa struct chứ không nằm ở dòng bị cảnh báo.
- **Khai báo biến toàn cục và macro** — một `#define MAX_LEN 64` có thể là toàn bộ câu trả lời cho một cảnh báo buffer overflow.
- **Vòng đời của con trỏ** — với use-after-free, cần biết *mọi* vị trí `free()`/`delete`/destructor trên toàn repo, không chỉ vị trí gần nhất.
- **Luồng dữ liệu** — source, các phép biến đổi trung gian, và sink; kèm câu hỏi mỗi phép biến đổi đó có phải sanitizer hợp lệ hay không.

Vài dòng code quanh vị trí cảnh báo — thứ mà đa số công cụ "LLM triage" đưa vào prompt — gần như không bao giờ chứa đủ những thông tin trên.

**2.2. Khi mô hình đúng về dữ kiện nhưng sai về kết luận**

Đây là một cảnh báo `php/tainted-filename` thật, tại `instructions.php:26` của DVWA. Một mô hình yếu, chạy một lượt, không có khả năng xin thêm ngữ cảnh, đã trả lời như sau (nguyên văn tiếng Anh do mô hình sinh ra, kèm bản dịch):

> - *"The potentially dangerous data originates from the `$_GET['doc']` superglobal, which is user input (line 26)."*
> - *"The data flows through `$selectedDocId` (line 27), then into `$readFile` via `$docs[$selectedDocId]['file']` (line 31)."*
> - *"There is a check using `array_key_exists()` to ensure that `$selectedDocId` exists in the `$docs` array (line 28-29). However, this only restricts the key to those defined in `$docs`, not the actual file path."*

Tạm dịch:

> - *"Dữ liệu nguy hiểm bắt nguồn từ superglobal `$_GET['doc']`, tức là input của người dùng (dòng 26)."*
> - *"Dữ liệu chảy qua `$selectedDocId` (dòng 27), rồi vào `$readFile` thông qua `$docs[$selectedDocId]['file']` (dòng 31)."*
> - *"Có một kiểm tra bằng `array_key_exists()` để đảm bảo `$selectedDocId` tồn tại trong mảng `$docs` (dòng 28-29). Tuy nhiên, kiểm tra này chỉ giới hạn key trong số các key đã định nghĩa ở `$docs`, chứ không giới hạn đường dẫn file thực tế."*

Kết luận của nó: **True Positive**, độ tin cậy cao, nhưng sự thật, đây **không phải lỗ hổng**.

Điều đáng nói là mô hình **không sai về bất kỳ dữ kiện nào**. Nó xác định đúng source, đúng luồng dữ liệu, đúng vị trí và bản chất của phép kiểm tra. Nó chỉ sai ở bước cuối: hàm `array_key_exists()` chỉ giới hạn key — nhưng điều đó vô hại, bởi vì toàn bộ giá trị trong mảng `$docs` là literal được hardcode. Thông tin quyết định nằm ở **định nghĩa của mảng `$docs`**, thứ không xuất hiện trong khoảng vài chục dòng code được đưa vào.

Khoảng cách giữa "dữ kiện đúng" và "kết luận đúng" chính là khoảng cách mà một hệ thống verification phải xóa bỏ — và cách xóa bỏ không phải là đổi sang mô hình đắt tiền hơn, mà là **cho mô hình quyền xin đúng ngữ cảnh mã nguồn mà nó đang thiếu**.

---

**3. Kiến trúc của VulnHunterX**

VulnHunterX không phải là một công cụ phát hiện lỗi (detector) mới. Nó hoạt động *phía sau* các detector, tiếp nhận cảnh báo của chúng, và quyết định cảnh báo nào đáng để một con người bỏ thời gian ra đọc.

```
Source  ──>  Static Analysis  ──>  SARIF  ──>  LLM Verification  ──>  Verdicts
(prepare)    (CodeQL/Semgrep/     (rule,     (guided questions,     (TP/FP/NMD
              OpenGrep)            file,      multi-turn context)    + score)
                                   line)
```

*[Hình 1: Luồng xác minh cảnh báo của VulnHunterX]*

| Giai đoạn | Lệnh | Mô tả |
|---|---|---|
| 1 | `prepare` | Chuẩn bị mã nguồn, xây dựng cơ sở dữ liệu và ngữ cảnh cần thiết |
| 2 | `analyze` | Quét lỗ hổng bằng các công cụ |
| 3 | `verify` | Xác minh các cảnh báo |
| 4 | `report` | Xuất báo cáo |

**3.1. Bộ guided questions theo từng loại lỗi**

Đây là thành phần cốt lõi. Thay vì một prompt chung chung, mỗi mã lỗi `ruleId` được định tuyến tới một bộ câu hỏi riêng. Hiện tại VulnHunterX có **397 bộ mẫu câu hỏi**, phân bố trên 7 bộ theo ngôn ngữ (C/C++ 62, Python 67, Java 59, JavaScript 57, Go 54, PHP 52, C# 45) cộng một bộ câu hỏi chung (generic).

**Bước 1 — chọn đúng bộ câu hỏi cho cảnh báo.** Mỗi công cụ SAST đặt tên mã lỗi theo một cách riêng, VulnHunterX khớp mã lỗi theo nhiều cách, sau đó khớp theo **CWE** để tìm đúng loại lỗi cần phân tích. Khi không khớp được mã lỗi, hệ thống mới trả về bộ câu hỏi generic:

| Thứ tự | Cách khớp mã lỗi | Ví dụ |
|---|---|---|
| 1 | Tên rule khớp chính xác tên bộ câu hỏi | CodeQL báo `cpp/use-after-free` → dùng bộ `cpp/use-after-free` |
| 2 | Chuẩn hóa dấu `-` thành `/` rồi khớp lại | dành cho engine đặt tên bằng dấu gạch ngang |
| 3 | Khớp theo tiền tố | `cpp/sql-injection` khớp bộ `cpp/sql` |
| 4 | Khớp trong cùng ngôn ngữ | cùng tiền tố `php/`, tên rule là chuỗi con của tên bộ câu hỏi |
| 5 | Khớp theo CWE | Semgrep báo `vulnhunterx.php.file-inclusion` — tên này không giống bất kỳ bộ nào, nhưng rule khai báo `metadata.cwe: CWE-98`; bảng `cwe_question_map` ánh xạ `CWE-98 → file-inclusion`, hệ thống dùng bộ `php/file-inclusion` |


**Bước 2 — thiết kế bộ câu hỏi.** Bộ câu hỏi gồm nhiều câu hỏi được xếp theo một trình tự cố định: neo mô hình vào đúng dòng code, ép nó thu thập dữ kiện có vị trí kiểm chứng được, sau đó mới đưa ra quy tắc kết luận. Ví dụ, bộ `cpp/use-after-free` gồm 10 câu, chia thành bốn nhóm:

| Nhóm câu hỏi | Nhiệm vụ | Sai lầm phổ biến của LLM |
|---|---|---|
| Câu 1 — neo | Trích nguyên văn câu lệnh tại dòng bị cảnh báo, nêu tên hàm chứa nó, phân loại dòng đó là lần dùng con trỏ, lời gọi free, hay chỉ là một khai báo hàm | Mô hình bình luận chung chung về cả đoạn code thay vì về đúng dòng mà SAST cảnh báo |
| Câu 2 — khoanh vùng | Khi đoạn code chứa nhiều hàm, xác định dòng bị cảnh báo thuộc hàm nào và chỉ suy luận về hàm đó | Kết tội chỉ vì bên cạnh có một hàm trông giống mẫu UAF hoặc có tên gợi ý là hàm lỗi |
| Câu 3–4 — thu thập dữ kiện | Truy nơi con trỏ được cấp phát; liệt kê **mọi** lời gọi free/delete kèm tên hàm, file và số dòng; đánh dấu free nào nằm trong nhánh có điều kiện | Kết luận dựa trên cảm giác, không có tọa độ nào để người review kiểm chứng lại |
| Câu 5–9 — kiểm tra phòng vệ | Con trỏ có được gán NULL sau free không; đường điều khiển ngắn nhất từ free tới lần dùng; con trỏ có thoát khỏi hàm không; có alias nào trỏ cùng vùng nhớ không; có được gán lại giữa chừng không | Bỏ sót đúng những lý do khiến một mẫu UAF nhìn thì đáng ngờ nhưng thực tế vô hại |
| Câu 10 — quy tắc kết luận | Quy định điều kiện tối thiểu để kết luận TP (nêu được bộ ba: vị trí free, vị trí dùng, đường điều khiển nối chúng) và bằng chứng bắt buộc để kết luận FP (gán NULL, cấp phát lại, nhánh không thể chạm tới, hoặc dòng bị đánh dấu chỉ là khai báo) | Mô hình đoán bừa khi thiếu dữ kiện, thay vì trả về `NEEDS_MORE_DATA` |

Chính thiết kế cấu trúc này cho phép các mô hình nhỏ vẫn hoạt động hiệu quả: Mô hình không phải tự suy nghĩ về những thứ cần kiểm tra, cũng không cần tự đặt ra ngưỡng để kết luận — những điều này đã nằm sẵn trong prompt của bộ câu hỏi. Việc còn lại của mô hình là phân tích code và trả lời.

Dưới đây là bốn câu đầu, trích nguyên văn tiếng Anh như được nạp vào prompt từ `config/prompts/cpp_questions.yaml`:

> - *"ANCHOR FIRST: quote the EXACT statement at the flagged line. Name the function it lives in. Classify the flagged line as one of: (a) a pointer USE (deref / read / write / pass-to-function), (b) a free/delete/destructor call, (c) a function signature or declaration, (d) something else. If (c) or (d), the SAST flag is suspect — record this and weight your verdict accordingly."*
> - *"If the snippet contains MULTIPLE functions (e.g. a vulnerable variant alongside a patched or test variant, or a helper alongside its caller), identify which function the flagged line belongs to. Reason ONLY about that function's behavior. Do NOT convict based on UAF patterns visible in sibling functions, regardless of how those functions are named."*
> - *"Where is the pointer at the flagged line ALLOCATED (malloc, calloc, new, strdup, custom allocator)? If allocation is in a DIFFERENT function, name that function — request 'caller:<func>' or 'all_callers:<func>' context if you cannot see it."*
> - *"List ALL free()/delete calls reachable from the flagged use — include the function name, file, and line number for EACH. If you cannot enumerate them from the snippet, request 'free_sites:<pointer_name>' context. Mark which frees are conditional (inside if/switch/error paths)."*

Tạm dịch:

> - *"NEO ĐẦU TIÊN: trích nguyên văn câu lệnh tại dòng bị đánh dấu. Nêu tên hàm chứa nó. Phân loại dòng đó là một trong các trường hợp: (a) một lần USE con trỏ (deref / đọc / ghi / truyền vào hàm), (b) một lời gọi free/delete/destructor, (c) một signature hoặc khai báo hàm, (d) thứ khác. Nếu là (c) hoặc (d), cảnh báo của SAST là đáng ngờ — hãy ghi nhận điều này và cân nhắc khi đưa ra verdict."*
> - *"Nếu đoạn code chứa NHIỀU hàm (ví dụ một biến thể có lỗi nằm cạnh một biến thể đã vá hoặc một biến thể test, hoặc một hàm helper nằm cạnh hàm gọi nó), hãy xác định dòng bị đánh dấu thuộc hàm nào. Chỉ suy luận về hành vi của hàm đó. KHÔNG kết tội dựa trên pattern UAF nhìn thấy ở các hàm anh em, bất kể các hàm đó được đặt tên như thế nào."*
> - *"Con trỏ tại dòng bị đánh dấu được CẤP PHÁT ở đâu (malloc, calloc, new, strdup, allocator tự viết)? Nếu việc cấp phát nằm ở hàm KHÁC, hãy nêu tên hàm đó — và yêu cầu ngữ cảnh `caller:<func>` hoặc `all_callers:<func>` nếu bạn không nhìn thấy nó."*
> - *"Liệt kê TẤT CẢ các lời gọi free()/delete có thể chạm tới từ vị trí sử dụng bị đánh dấu — kèm tên hàm, file và số dòng cho TỪNG cái. Nếu không liệt kê được từ đoạn code hiện có, hãy yêu cầu ngữ cảnh `free_sites:<pointer_name>`. Đánh dấu những lời gọi free nào là có điều kiện (nằm trong nhánh if/switch/xử lý lỗi)."*

Ngoài danh sách câu hỏi, mỗi bộ câu hỏi còn có các trường điều khiển hành vi của engine. Ví dụ, với `cpp/use-after-free`:

- `additional_context: [free_sites, caller, all_callers, struct, callees, destructor, field_writes]` — danh sách các ngữ cảnh mà mô hình được phép xin thêm cho loại lỗi này.
- `context_hint` — gợi ý thứ tự: lấy `free_sites` của con trỏ trước, rồi mới tới nơi con trỏ sinh ra, định nghĩa kiểu, và destructor của lớp sở hữu nó.
- `min_iterations: 3` — số lượt hội thoại truy vấn tối thiểu, tức là mô hình **không được phép** kết luận ngay ở lượt truy vấn đầu tiên.

**3.2. Buộc trả lời trước, kết luận sau**

Bộ câu hỏi chỉ có tác dụng nếu mô hình bị *buộc* phải trả lời hết trước khi được kết luận. Ràng buộc này nằm trong system prompt, dưới dạng một quy trình sáu bước theo đúng thứ tự:

| Bước | Yêu cầu | Vì sao cần |
|---|---|---|
| 0 | **Định vị dòng bị cảnh báo**: tìm theo số dòng trong khối code có đánh số, trích nguyên văn nội dung dòng đó, xác nhận cấu trúc mà rule mô tả có thật sự nằm ở đó | Chặn kiểu suy luận về một đoạn code khác với đoạn mà SAST đang cảnh báo |
| 1 | **Nhận diện lớp lỗ hổng** từ rule id và mô tả | Chọn đúng khung suy luận |
| 2 | **Trả lời từng câu hỏi dẫn dắt**, chỉ dựa trên code được cung cấp, có trích số dòng; nếu không nhìn thấy thì phải ghi rõ *"Not visible in provided context"* | Buộc mọi khẳng định phải có tọa độ kiểm chứng, và buộc thừa nhận khi thiếu dữ kiện |
| 3 | **Truy vết luồng dữ liệu**: source → biến đổi/sanitizer → sink, liệt kê từng bước kèm số dòng | Tách "có đường đi" khỏi "có vẻ nguy hiểm" |
| 4 | **Đánh giá khả năng chạm tới và khai thác** của đường đi đó | Một sink nguy hiểm trên nhánh không thể chạm tới thì không phải lỗ hổng |
| 5 | **Chỉ đến lúc này** mới được đưa ra verdict | |

Ngoài ra còn có bộ ba nguyên tắc trong quy trình suy luận, quan trọng không kém bản thân các câu hỏi:

- **Bằng chứng cụ thể.** Để kết luận *False Positive* (cảnh báo giả), mô hình bắt buộc phải chỉ ra trong code biện pháp kiểm tra/phòng chống **cụ thể, nhìn thấy được** — một phép kiểm tra điều kiện biên, một lời gọi sanitizer, hay một cơ chế bảo vệ của framework. Nguyên văn ràng buộc trong prompt: *"Absence of evidence of a vulnerability is NOT evidence of safety"* — không thấy dấu hiệu lỗ hổng không có nghĩa là an toàn. Mô hình cũng bị cấm suy ra sự an toàn từ tên hàm hay từ các thuộc tính như `static`, `__init`.
- **Chưa có bằng chứng thì không được kết luận.** Nếu dòng bị đánh dấu không có mặt trong đoạn code được cung cấp, mô hình **không được** trả lời *False Positive* — nó phải trả về *Needs More Data* (cần thêm dữ liệu) và yêu cầu đúng phần code còn thiếu. Đây là ràng buộc chặn cách tiếp cận thường thấy của LLM khi suy luận: bịa ra kết luận an toàn cho một dòng code mà nó chưa từng đọc.
- **Rule chỉ định vị sink, không quyết định lớp lỗi.** Nếu sink bị đánh dấu thật sự khai thác được, mô hình phải kết luận *True Positive* ngay cả khi lớp lỗ hổng thực tế khác với CWE ghi trong rule — và phải gọi đúng tên lớp lỗi thật trong phần lập luận. Ngược lại, nó bị cấm "vay" một lỗi khác ở dòng khác để hợp thức hóa cảnh báo đang xét.

Prompt cũng hướng dẫn cho các mô hình cách đọc metadata của rule cho đúng: `precision: high` nói lên độ tin cậy của **pattern** trên toàn bộ corpus, không nói gì về việc **trường hợp này** có khai thác được hay không; `security-severity` là mức nghiêm trọng trong kịch bản xấu nhất của rule, chỉ dùng để sắp thứ tự ưu tiên đọc, không được dùng làm lý do nghiêng về True Positive.

Kết quả của toàn bộ ràng buộc trên làm nâng cao chất lượng phân tích cảnh báo của các kỹ sư an toàn thông tin, VulnHunterX trả về **một kết luận kèm một số dòng code cụ thể** cho cảnh báo, chỉ cần xem trong vài giây là có thể tự đưa ra kết luận.

**3.3. Mở rộng ngữ cảnh nhiều lượt (multi-turn)**

Khi phát hiện  thiếu dữ kiện, mô hình có thể yêu cầu thêm ngữ cảnh từ một bộ dữ liệu cố định đã được trích xuất sẵn:

| Yêu cầu | Nội dung trả về |
|---|---|
| `caller:` / `all_callers:` | Code của hàm gọi / toàn bộ hàm gọi (đang giới hạn tối đa 10) |
| `function:` / `callees:` / `callee_bodies:` | Thân hàm sink, danh sách hàm được gọi, và thân của chúng |
| `struct:` / `typedef:` / `enum:` | Định nghĩa kiểu dữ liệu, type alias, enum kèm giá trị |
| `global:` / `macro:` | Khai báo biến toàn cục, định nghĩa macro |
| `free_sites:` | Mọi vị trí free()/delete/destructor của một con trỏ trên toàn repo (C/C++) |
| `destructor:` / `field_writes:` | Thân destructor, mọi vị trí ghi vào một field (C/C++, phục vụ RAII và TOCTOU) |
| `framework_sanitizers:` / `framework_guards:` | Ranh giới validation và auth guard ở tầng framework (ví dụ `ValidationPipe`, `APP_GUARD` của NestJS) |

Kèm theo đó, prompt luôn chứa **luồng dataflow do chính engine SAST trích ra**, đã được gán nhãn `[SOURCE]` / `[TRANSFORM]` / `[SINK]` cho từng bước. VulnHunterX không cố tự dựng lại DFG — nó tái sử dụng kết quả phân tích luồng dữ liệu vốn là thế mạnh của các công cụ CodeQL hay tree-sitter, bổ sung phần mà SAST không cung cấp là call graph, định nghĩa kiểu, và vòng đời đối tượng.

Kết quả, số lượt hội thoại trung bình cho một cảnh báo là **2,49 lượt**.

**3.4. Đầu ra**

Mô hình không được trả lời tự do. Nó phải trả về một bộ dữ liệu có cấu trúc JSON, gồm các trường:

| Trường | Nội dung |
|---|---|
| `answers[]` | Phiếu trả lời cho mỗi câu hỏi, có trích số dòng |
| `data_flow` | Luồng dữ liệu đã truy vết, dạng `source (dòng N) → transform (dòng M) → sink (dòng K)` |
| `verdict` | `True Positive` / `False Positive` / `Needs More Data` |
| `confidence` | Giá trị `High` / `Medium` / `Low` |
| `confidence_score` | Điểm số 0.0–1.0; nếu mô hình không tự cho điểm, engine quy đổi từ mức định tính (High = 0.85, Medium = 0.6, Low = 0.3) |
| `reasoning` | Một vài câu giải thích, tham chiếu đến phiếu trả lời và luồng dữ liệu |
| `context_needed[]` | Danh sách ngữ cảnh còn thiếu, dùng để kích hoạt vòng hội thoại tiếp theo |

Bên cạnh phần do mô hình sinh, engine ghi thêm các thông tin của lần chạy đó: `iterations` (số lượt hội thoại đã thực hiện), `model`, `timestamp`, `elapsed_seconds`, `input_tokens` / `output_tokens` / `cached_input_tokens`, và `cost_usd`. Nhờ vậy mọi con số chi phí trong mục 4 đều truy ngược được về từng finding cụ thể, chứ không phải ước lượng.

Dưới đây là một verdict thật, đã lược bớt phần metadata, cho cảnh báo `double-free` mà Semgrep báo tại `dvcp.c:62`:

```json
{
  "finding": {
    "rule_id": "c.lang.security.double-free.double-free",
    "message": "Variable 'buff1' was freed twice. This can lead to undefined behavior.",
    "file": "repos/c/dvcp/dvcp.c",
    "start_line": 62,
    "precision": "very-high",
    "cwe_ids": ["CWE-415"],
    "tool": "Semgrep"
  },
  "verdict": "False Positive",
  "confidence": "Low",
  "confidence_score": 0.55,
  "reasoning": "The flagged free is in a different file/function than the only other known free sites, and no control-flow path linking them is provided. Without evidence of a prior free of the same memory in the same execution context, the double-free claim is unsupported.",
  "answers": [
    "Flagged line: dvcp.c:62 `free(buff1);` — a free call.",
    "Only the `if` block is shown; the containing function is unknown. Free sites from `imgRead.c` are in a different file.",
    "Only two free sites for buff1 listed: imgRead.c:59 and imgRead.c:62 (both in ProcessImage). The flagged free at dvcp.c:62 is not accounted for in that list.",
    "No code path shown that connects the flagged free to any other free of the same pointer.",
    "No NULL assignment visible."
  ],
  "iterations": 3,
  "model": "deepseek-v4-flash",
  "input_tokens": 10324,
  "output_tokens": 3654,
  "cached_input_tokens": 6016
}
```

Tạm dịch phần `reasoning`: *"Lời gọi free bị đánh dấu nằm ở file và hàm khác với hai vị trí free duy nhất đã biết, và không có đường điều khiển nào nối chúng lại. Khi chưa có bằng chứng rằng cùng vùng nhớ đó đã được free trước đó trong cùng một ngữ cảnh thực thi, khẳng định double-free là không có cơ sở."*

Bản ghi này minh họa những gì mục 3.2 mô tả. Rule khai báo `precision: very-high`, tuy nhiên mô hình không lấy đó làm bằng chứng. Nó liệt kê được **chính xác** hai vị trí free đã biết kèm file và số dòng, chỉ ra rằng dòng bị cảnh báo không nằm trong số đó, và hạ độ tin cậy xuống `Low` thay vì tuyên bố chắc chắn — một tín hiệu đủ để người review biết đây là finding nên liếc qua trước khi đóng.

Ba giá trị verdict được dùng như sau trong thực tế vận hành:

- **`True Positive`** — đưa vào hàng đợi xử lý, sắp thứ tự theo `confidence_score` và mức nghiêm trọng.
- **`False Positive`** — đóng lại, nhưng phiếu trả lời vẫn được lưu để có thể kiểm tra lại về sau. Đây là điểm khác biệt so với việc lọc bằng regex hay danh sách loại trừ: mỗi lần loại bỏ đều kèm lý do.
- **`Needs More Data`** — trạng thái được giữ lại **một cách có chủ đích**. Một hệ thống triage biết nói "tôi không đủ dữ kiện" hữu ích hơn hẳn một hệ thống luôn luôn trả lời, vì nó biến phần khó thành một danh sách ngắn cần người xem, thay vì trộn lẫn những phỏng đoán may rủi vào cùng với các kết luận có căn cứ. 

Cuối cùng, giai đoạn `report` gom toàn bộ verdict thành một báo cáo Markdown gồm phần tóm tắt và phần chi tiết từng finding kèm phiếu trả lời.

---

**4. Kết quả thực nghiệm**

**4.1. Bộ hồi quy nội bộ**

Bộ này gồm 125 finding từ bốn mục tiêu cố tình chứa lỗi — **dvcp** (C), **dvwa** (PHP), **insecure-coding-examples** (C/C++), **nodegoat** (JavaScript) — với ground-truth dựng thủ công: 88 lỗi thật, 37 cảnh báo giả.

| | Precision | Recall |
|---|---|---|
| SAST thô (coi mọi cảnh báo là thật) | 70% | 100% |
| **VulnHunterX** | **92%** | **95%** |

Chi phí cho toàn bộ 125 finding: **14,58 USD**, tương đương khoảng **0,12 USD/finding**, với tỉ lệ prompt-cache hit 69%.

**4.2. Các bộ dữ liệu công khai**

*OWASP BenchmarkPython (300 case):*

| Cách tiếp cận | Model | Precision | Recall | Giảm FP |
|---|---|---|---|---|
| raw-sast | — | 37,7% | 100% | 0% |
| ablation-zero (không câu hỏi) | DeepSeek | 77,3% | 96,5% | 82,9% |
| ablation-generic (câu hỏi chung) | DeepSeek | 81,1% | 94,7% | 86,6% |
| **vulnhunterx (guided questions)** | **DeepSeek** | **87,3%** | **98,2%** | **91,4%** |


*Tổng hợp bốn bộ dữ liệu, với model mạnh nhất được thử (DeepSeek):* giảm false positive **78,6%–91,4%** trong khi vẫn giữ lại **87,5%–98,2%** số lỗi thật. Trên toàn bộ các model đã thử, recall dao động trong khoảng **86%–100%** — pipeline hiếm khi vứt nhầm lỗ hổng thật.

**4.3. Không cần LLM mạnh: mô hình nhỏ và mô hình chạy local vẫn hoạt động tốt**

Đây là kết quả có giá trị thực tiễn cao nhất, vì nó quyết định chi phí vận hành. Cùng bộ OWASP BenchmarkPython, cùng pipeline, chỉ thay model:

| Model | Precision | Recall | Giảm FP | Chi phí |
|---|---|---|---|---|
| raw-sast (không LLM) | 37,7% | 100% | 0% | — |
| ollama-qwen3-coder (chạy local) | 65,3% | 99,1% | 68,5% | **0 USD** |
| gpt-4.1-mini | 82,7% | 97,4% | 87,7% | 1,10 USD |
| DeepSeek | 87,3% | 98,2% | 91,4% | 0,40 USD |

Một mô hình **mini** đưa precision từ 37,7% lên 82,7% — tức loại bỏ **87,7%** khối lượng triage vô ích — và chỉ kém mô hình mạnh nhất 4,6 điểm. Một mô hình chạy **hoàn toàn local, chi phí API bằng 0**, vẫn giảm được hơn hai phần ba số cảnh báo giả trong khi giữ 99,1% lỗ hổng thật.

Quan trọng hơn, hãy nhìn phần đóng góp của scaffolding đối với chính mô hình yếu đó. Với gpt-4.1-mini trên cùng bộ dữ liệu: không có câu hỏi dẫn dắt → 64,0% precision; với bộ guided questions theo rule → **82,7%**. Bộ câu hỏi đúng loại lỗi mang lại cho mô hình nhỏ **hơn 18 điểm precision** — nhiều hơn hẳn phần chênh lệch giữa nó và mô hình lớn.

Đánh giá giá thành khi sử dụng LLM:

| Model | Precision | Recall | Chi phí cho cả bộ |
|---|---|---|---|
| gpt-5 | 78,4% | 85,9% | 16,75 USD |
| DeepSeek | 82,1% | 87,5% | không tính được (*) |
| gpt-4.1-mini | 74,7% | 89,9% | 0,73 USD |
| ollama-qwen3-coder (local) | 70,5% | 87,8% | **0 USD** |

Mô hình local chỉ kém `gpt-5` **7,9 điểm precision** trong khi `gpt-5` tốn 16,75 USD cho cùng khối lượng công việc — và bản thân `gpt-5` cũng không phải model tốt nhất trong bảng. Với đội bảo mật không được phép gửi source code ra ngoài, đây là điểm khác biệt giữa "dùng được" và "không dùng được".

**4.4. Hạn chế**

Ưu thế của mô hình nhỏ không đồng đều giữa các lớp lỗi. Trên bộ Juliet C/C++ — vốn kiểm tra khả năng suy luận về memory safety — gpt-4.1-mini chỉ giảm được **23,9%** false positive, trong khi DeepSeek đạt **82,2%** trên cùng dataset và cùng pipeline. Hai lần chạy model local trên OWASP BenchmarkJava thì abstain (`NEEDS_MORE_DATA`) trên gần như toàn bộ finding — được ghi nhận là "giảm 100% FP" nhưng thực chất là một thất bại đội lốt thành công, và các dòng này vẫn được giữ nguyên trong bảng so sánh công bố.

Kết luận thực tế: **với các lớp lỗi web phổ biến (injection, path traversal, XSS, deserialization), một mô hình nhỏ hoặc local cộng scaffolding tốt là đủ dùng; với suy luận về các lỗi liên quan đến bộ nhớ trong C/C++, scaffolding không thay thế được năng lực mô hình.**

---

**5. Một số ưu điểm khác của VulnHunterX**

VulnHunterX hỗ trợ **8 ngôn ngữ**, phủ cả hai nhóm:

| Nhóm | Ngôn ngữ | Nguồn ngữ cảnh cho verification |
|---|---|---|
| Biên dịch | C, C++ | CodeQL DB — 14 query trích xuất: functions, callers, structs, globals, macros, enums, typedefs, free_sites, destructors, field_writes… |
| Biên dịch | Java | CodeQL DB — functions, callers, classes |
| Biên dịch | Go, C# | CodeQL DB — functions, callers, classes |
| Thông dịch | Python | CodeQL DB — functions, callers, classes |
| Thông dịch | JavaScript | CodeQL DB — functions, callers, classes |
| Thông dịch | PHP | tree-sitter (khi không dựng được CodeQL database) |

Điểm đáng chú ý về mặt kỹ thuật là **cơ chế fallback**: khi không dựng được CodeQL database — có thể do ngôn ngữ không được hỗ trợ, build thất bại, hoặc do repo thiếu toolchain — hệ thống chuyển sang trích xuất ngữ cảnh bằng tree-sitter, vốn chỉ cần parse cú pháp chứ không cần biên dịch. Chất lượng ngữ cảnh thấp hơn (không có call graph liên thủ tục chính xác), nhưng pipeline verification vẫn hoạt động được.

Về phía SAST, hệ thống hoạt động được với ba engine (CodeQL, Semgrep, OpenGrep) và năm profile rule từ `standard` tới `full`, trong đó `full` có thêm 64 query CodeQL và 103 rule Semgrep tự viết lên các suite có sẵn. Về phía LLM, VulnHunterX hỗ trợ hầu hết provider phổ biến của LiteLLM: OpenAI, Anthropic, Gemini, DeepSeek, và Ollama (local hoặc cloud).

```bash
vuln-hunter-x scan --url https://github.com/org/app.git --lang python --profile full --limit 10
```

---

**6. Hạn chế của công cụ VulnHunterX**

- **Lỗi thuộc dạng "thiếu kiểm soát" nằm ngoài tầm với.** Thiếu phân quyền, CSRF middleware bị tắt, không có rate limiting — SAST không phát hiện được một cách đáng tin cậy, nên cũng không có gì để verifier thẩm định. Báo cáo của VulnHunterX luôn kèm cảnh báo về giới hạn phạm vi đúng vì lý do này.
- **Chất lượng phụ thuộc vào chất lượng của SAST đầu vào.** Verifier chỉ có thể loại bớt cảnh báo giả; nó không tạo ra được cảnh báo mà engine phía trước đã bỏ sót. Recall của toàn hệ thống bị chặn trên bởi recall của SAST.

---

**7. Kết luận**

Bài toán của SAST trong thực tế không phải là phát hiện, mà là thẩm định. Và thẩm định không phải là bài toán cần một mô hình thông minh hơn — nó là bài toán cần **đúng ngữ cảnh, được cung cấp đúng lúc, cho một mô hình bị buộc phải trả lời đúng những câu hỏi mà loại lỗi đó đòi hỏi**.

Khi tách được hai thứ đó ra, kết quả là: precision tăng từ 37,7% lên 82,7% *với một mô hình mini*, và lên 65,3% với một mô hình chạy hoàn toàn trên máy nội bộ, chi phí API bằng không. Phần lớn giá trị nằm ở bộ 397 câu hỏi dẫn dắt và cơ chế xin ngữ cảnh nhiều lượt, chứ không nằm ở kích thước mô hình.

VulnHunterX là mã nguồn mở theo giấy phép MIT:

```bash
git clone https://github.com/vinsoc-cyber/VulnHunterX.git && cd VulnHunterX
uv venv --python python3.12 .venv && source .venv/bin/activate
uv pip install -e ".[dev]"
cp env.example .env        # thêm API key của provider
vuln-hunter-x check-env    # kiểm tra toolchain
vuln-hunter-x interactive  # wizard, không cần nhớ flag
```

**VinSOC Research Team.**

---

***Tài liệu tham khảo***

*[1] CyberArk Labs – Vulnhalla: Picking the True Vulnerabilities from the CodeQL Haystack – CyberArk Threat Research Blog (https://www.cyberark.com/resources/threat-research-blog/vulnhalla-picking-the-true-vulnerabilities-from-the-codeql-haystack)*

*[2] VulnHunterX – Source code và tài liệu – GitHub Repository (https://github.com/vinsoc-cyber/VulnHunterX)*

*[3] OWASP Benchmark Project – Bộ dữ liệu ground-truth cho Java và Python (https://owasp.org/www-project-benchmark/)*

*[4] NIST SARD – Juliet Test Suite for C/C++ v1.3.1 (https://samate.nist.gov/SARD/test-suites)*

*[5] SecLLMHolmes – Benchmark đánh giá năng lực suy luận lỗ hổng của LLM (https://github.com/ai4cloudops/SecLLMHolmes)*

*[6] GitHub – CodeQL CLI Documentation (https://codeql.github.com/docs/codeql-cli/)*

*[7] BerriAI – LiteLLM: unified interface cho hơn 100 LLM provider (https://github.com/BerriAI/litellm)*

---