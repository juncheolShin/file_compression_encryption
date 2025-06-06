//압축과 암호화/복호화를 담당하는 cpp 파일입니다.
#include "hufcrypt_core.h"
#include "file_compression_encryption.h"
#define DBG(expr) do { std::cerr << "[DBG] " #expr " = " << (expr) << '\n'; } while(0)

using Byte = unsigned char;
using Bytes = std::vector<Byte>;
// ──────────────────────────────
// AES-GCM 대칭키 암호화/복호화 구현
// 비밀번호 + salt로 키 유도(PBKDF2), 이후 GCM 암호화 수행
// ──────────────────────────────
namespace crypto {
    constexpr size_t KEY_LEN = 32; // 256‑bit
    constexpr size_t IV_LEN = 12; // GCM 권장 96‑bit
    constexpr size_t TAG_LEN = 16; // GCM 태그
    constexpr size_t SALT_LEN = 16; //Salt 길이

    class AesGcm {
    public:
        //암호화 함수
        static bool encrypt(const Bytes& plaintext,
            const std::string& password,
            Bytes& ciphertext, Bytes& salt, Bytes& iv, Bytes& tag);

        //복호화 함수
        static bool decrypt(const Bytes& ciphertext,
            const std::string& password,
            const Bytes& salt, const Bytes& iv, const Bytes& tag,
            Bytes& plaintext);
    private:
        //PBKDF2를 이용한 키 유도 함수
        static Bytes deriveKey(const std::string& password, const Bytes& salt);

    };

    Bytes AesGcm::deriveKey(const std::string& password, const Bytes& salt) {
        Bytes key(KEY_LEN);
        PKCS5_PBKDF2_HMAC(password.c_str(), password.size(), // password , salt 정보 를 입력 받음
            salt.data(), salt.size(),
            150000, EVP_sha256(), KEY_LEN, key.data()); // 반복 횟수 , 해싱 방식 , 키 길이 , 키 값
        return key;
    }

    bool AesGcm::encrypt(const Bytes& plaintext, const std::string& password,
        Bytes& ciphertext, Bytes& salt, Bytes& iv, Bytes& tag) { // 암호화 과정
        salt.resize(SALT_LEN);
        RAND_bytes(salt.data(), SALT_LEN); //랜덤 salt 설정 
        iv.resize(IV_LEN);
        RAND_bytes(iv.data(), IV_LEN); //랜덤 iv 설정
        Bytes key = deriveKey(password, salt);

        ciphertext.resize(plaintext.size());
        tag.resize(TAG_LEN);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        int len = 0, out_len = 0;
        if (!ctx) return false;

        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) return false;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr);
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());

        if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size())) return false;
        out_len = len;
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) return false;
        out_len += len;
        ciphertext.resize(out_len); // 결과값 검사 과정

        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag.data());
        EVP_CIPHER_CTX_free(ctx);
        return true;
    }

    bool AesGcm::decrypt(const Bytes& ciphertext, const std::string& password,
        const Bytes& salt, const Bytes& iv, const Bytes& tag,
        Bytes& plaintext) {
        Bytes key = deriveKey(password, salt);
        plaintext.resize(ciphertext.size());
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        int len = 0, out_len = 0;
        if (!ctx) return false;
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) return false;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());
        if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size())) return false;
        out_len = len;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), (void*)tag.data());
        if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) return false; // tag 검증
        out_len += len;
        plaintext.resize(out_len);
        EVP_CIPHER_CTX_free(ctx);
        return true;
    }
} // namespace crypto

// ──────────────────────────────
// Huffman 압축/해제 구현
// 내부에서 트리를 만들고, 바이트 단위 인코딩/디코딩 수행
// ──────────────────────────────
namespace huffman {
    //압축 트리의 노드 정의
    class Node {
    public:
        Byte  byte;
        uint64_t freq;
        Node* left = nullptr;
        Node* right = nullptr;
        Node(Byte b, uint64_t f) : byte(b), freq(f) {}
        Node(Node* l, Node* r) : byte(0), freq(l->freq + r->freq), left(l), right(r) {}
        Node() : byte(0), freq(0) {};
        //리프 노드 판별
        bool isLeaf() const { return !left && !right; }
    };

    struct NodeCmp {
        bool operator()(Node* a, Node* b) const { return a->freq > b->freq; }
    };

    // 압축을 담당하는 Huffman codec
    class Codec {
    public:
        // 입력 바이트로부터 Huffman tree 생성
        void build(const Bytes& data);
        // 압축 수행: Huffman 코드로 인코딩
        Bytes encode(const Bytes& data) const;
        // 복원 수행: Huffman 코드로 디코딩
        Bytes decode(const Bytes& bitstream) const;
        // 트리를 바이트 형태로 직렬화 (헤더 저장용)
        Bytes serializeTree() const;               // 리프 테이블 헤더용
        // 직렬화된 트리로부터 다시 트리 생성
        void  deserializeTree(const Bytes& blob); // 복구
    private:
        void buildCode(Node* node, std::string cur); // 재귀적 코드 빌드
        void freeTree(Node* node); // 트리 메모리 해제
        Node* root = nullptr;
        std::array<std::string, 256> table; // byte → code
    };

    //데이터에서 각 바이트(Byte)의 등장 횟수를 셈.
    void Codec::build(const Bytes& data) {
        if (data.empty()) {                     
            root = nullptr;
            table.fill("");
            return;
        }
        std::array<uint64_t, 256> freq{};
        for (Byte b : data) ++freq[b]; //std::array로 각 바이트의 등장 빈도를 저장
        std::priority_queue<Node*, std::vector<Node*>, NodeCmp> pq; //최소 힙을 이용하여 빈도가 낮은 것부터 트리로 묶음.
        for (int i = 0; i < 256; ++i) if (freq[i]) pq.push(new Node((Byte)i, freq[i]));
        if (pq.size() == 1) pq.push(new Node(0, 1)); // 단일 문자 예외
        while (pq.size() > 1) {
            Node* a = pq.top(); pq.pop();
            Node* b = pq.top(); pq.pop();  //두 개의 최소 빈도 노드를 묶어 부모 노드를 생성. 반복하여 루트 노드 1개가 남을 때까지 수행.
            pq.push(new Node(a, b));
        }
        root = pq.top();
        buildCode(root, "");
    }

    //왼쪽으로 가면 0, 오른쪽으로 가면 1을 추가하여 이진 코드 생성.
    void Codec::buildCode(Node* node, std::string cur) {
        if (node->isLeaf()) {
            table[node->byte] = cur.empty() ? "0" : cur;
            return;
        }
        buildCode(node->left, cur + '0');
        buildCode(node->right, cur + '1');
    }

    //비트 문자열을 생성 후, 8비트 단위로 묶어 실제 Byte 벡터로 변환.
    Bytes Codec::encode(const Bytes& data) const {
        std::string bits;
        bits.reserve(data.size() * 8);
        for (Byte b : data) bits += table[b];
        size_t pad = (8 - bits.size() % 8) % 8;
        bits.append(pad, '0');
        Bytes out((bits.size() + 7) / 8);
        for (size_t i = 0; i < bits.size(); ++i)
            if (bits[i] == '1') out[i / 8] |= 1 << (7 - (i % 8));
        out.insert(out.begin(), (Byte)pad); // 첫 바이트에 패딩 길이 저장
        return out;
    }

    //비트 하나씩 따라가며 트리를 탐색, 리프에 도달하면 해당 바이트를 출력.
    Bytes Codec::decode(const Bytes& bitstream) const {
        DBG(bitstream.size());
        if (bitstream.empty()) return {};
        size_t pad = bitstream[0];
        std::string bits;
        for (size_t i = 1; i < bitstream.size(); ++i)
            for (int b = 7; b >= 0; --b)
                bits.push_back((bitstream[i] >> b & 1) ? '1' : '0');
        if (pad) bits.erase(bits.end() - pad, bits.end());
        Bytes out;
        Node* node = root;
        for (char c : bits) {
            if (!node) { std::cerr << "NULL node!\n"; return {}; }
            node = (c == '0') ? node->left : node->right;
            if (node->isLeaf()) {
                out.push_back(node->byte);
                node = root;
            }
        }
        return out;
    }

    //문자와 이진코드 간의 매칭 정보를 압축된 파일 앞에 직렬화된 트리(blob)형태로 저장
    Bytes Codec::serializeTree() const {
        // 간단히: [leaf_count][leaf_byte, code_length, code_bits...]* 
        std::vector<std::uint8_t> blob;
        uint16_t leaves = 0;
        for (auto& s : table) if (!s.empty()) ++leaves;
        blob.push_back(leaves >> 8); blob.push_back(leaves & 0xFF);
        for (int b = 0; b < 256; ++b) {
            const std::string& code = table[b];
            if (code.empty()) continue;
            blob.push_back((Byte)b);
            blob.push_back((Byte)code.size());
            // 8bits 로 패딩
            std::string padded = code;
            size_t pad = (8 - padded.size() % 8) % 8;
            padded.append(pad, '0');
            for (size_t i = 0; i < padded.size(); i += 8) {
                Byte v = 0;
                for (int j = 0; j < 8; ++j) if (padded[i + j] == '1') v |= 1 << (7 - j);
                blob.push_back(v);
            } // ex)
            //A: 0  B: 10 C : 11
            // -> leaf_count = 3 ('A', 1, 0) ('B', 2, 10) ('C', 2, 11)
            //-> 직렬화 
            //00 03                     // leaf_count = 3
            //41 01 00                  // 'A', len=1, bits=00000000 (41 = ASCII 'A')
            //42 02 80                  // 'B', len=2, bits=10000000
            //43 02 C0                  // 'C', len=2, bits=11000000
        }
        return blob;
    }

    //ㅣeaf_count 만큼 반복
    //[문자, 길이, 비트코드]를 하나씩 읽음
    //길이만큼 비트를 추출하여 허프만 트리 복원
    void Codec::deserializeTree(const Bytes& blob) {
        size_t idx = 0;
        uint16_t leaves = (blob[idx] << 8) | blob[idx + 1]; idx += 2;
        std::vector<std::pair<Byte, std::string>> entries;
        for (int i = 0; i < leaves; ++i) {
            Byte sym = blob[idx++];
            Byte len = blob[idx++];
            size_t bitBytes = (len + 7) / 8;
            std::string bits;
            for (size_t j = 0; j < bitBytes; ++j) {
                Byte v = blob[idx++];
                for (int b = 7; b >= 0; --b) bits.push_back((v >> b & 1) ? '1' : '0');
            }
            bits.resize(len);
            entries.emplace_back(sym, bits);
        }
        // rebuild tree
        if (root) freeTree(root);
        root = new Node();
        for (auto& [sym, bits] : entries) {
            Node* cur = root;
            for (char c : bits) {
                Node*& next = (c == '0') ? cur->left : cur->right;
                if (!next) next = new Node();
                cur = next;
            }
            cur->byte = sym; cur->left = cur->right = nullptr; // leaf
        }
        // fill table
        table.fill("");
        buildCode(root, "");
    }

    void Codec::freeTree(Node* node) {
        if (!node) return;
        freeTree(node->left);
        freeTree(node->right);
        delete node;
    }
} // namespace huffman

// ──────────────────────────────
// 파일 포맷 관련 구조 정의
// 헤더를 통해 암호화 알고리즘, 트리 길이 등 복호화 정보를 저장
// ──────────────────────────────
namespace filefmt {
    const std::array<char, 4> MAGIC = { 'H','U','F','1' }; // Magic bytes for 파일 식별
    enum Alg : Byte { ALG_AES_GCM = 1 }; // 현재는 AES-GCM만 사용

    #pragma pack(push, 1)
    struct Header { // 구조체는 내부용, 파일 바이트 배열로만 사용
        std::array<char, 4> magic = { 'H','U','F','1' };;
        Byte alg_id = 1;
        Byte salt_len = crypto::SALT_LEN;
        Byte iv_len = crypto::IV_LEN;
        Byte tag_len = crypto::TAG_LEN;
        uint32_t tree_len = 0;      // 허프만 트리 blob 크기
        uint32_t data_len = 0;      // 암호문 길이
    };
    #pragma pack(pop)

    void writeHeader(std::ofstream& ofs, const Header& h) { // 헤더를 바이너리로 파일에 기록
        ofs.write(reinterpret_cast<const char*>(&h), sizeof(Header));
    }
    Header readHeader(std::ifstream& ifs) { // 파일에서 헤더를 읽음
        Header h; ifs.read(reinterpret_cast<char*>(&h), sizeof(Header)); return h;
    }
} // namespace filefmt

/* 유틸: 파일 읽기/쓰기 (static) --------------------------------- */
static Bytes readFile(const std::string& path,
    std::function<void(std::size_t, std::size_t)> prog = {})
{
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    std::size_t total = ifs.tellg();
    Bytes data(total);
    ifs.seekg(0);
    ifs.read(reinterpret_cast<char*>(data.data()), total);
    if (prog) prog(total, total);
    return data;
}
static void writeFile(const std::string& path,
    const Bytes& data,
    std::function<void(std::size_t, std::size_t)> prog = {})
{
    std::ofstream ofs(path, std::ios::binary);
    ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
    if (prog) prog(data.size(), data.size());
}

/* public API ---------------------------------------------------- */
bool hufcrypt::process(bool enc,
    const std::string& inPath,
    const std::string& outPath,
    const std::string& pw,
    std::function<void(std::size_t, std::size_t)> progress,
    logEmitter* emitter)
{
    try
    {
        if (enc)
        {
            /* 1. 파일 읽기 */  
            if (emitter) emit emitter->logMessage("파일을 읽어오는 중...");
            Bytes plain = readFile(inPath, progress);
            if (emitter) emit emitter->logMessage("파일 읽기 완료...");

            /* 2. 허프만 압축 */
            huffman::Codec codec;
            codec.build(plain);
            if (emitter) emit emitter->logMessage("파일 압축 중...");
            Bytes treeBlob = codec.serializeTree();
            Bytes encoded = codec.encode(plain);
            if (emitter) emit emitter->logMessage("파일 압축 완료...");

            /* 3. AES-GCM 암호화 */
            Bytes cipher, salt, iv, tag;
            if (emitter) emit emitter->logMessage("파일 암호화 중...");
            if (!crypto::AesGcm::encrypt(encoded, pw,
                cipher, salt, iv, tag)) {
                if (emitter) emit emitter->logMessage("파일 암호화 실패...");
                throw std::runtime_error("encrypt failed");
            }
            if (emitter) emit emitter->logMessage("파일 암호화 완료...");

            /* 4. 헤더+바디 쓰기 */
            filefmt::Header hdr;
            if (emitter) emit emitter->logMessage("파일 작성중...");
            hdr.tree_len = static_cast<uint32_t>(treeBlob.size());
            hdr.data_len = static_cast<uint32_t>(cipher.size());

            std::ofstream ofs(outPath, std::ios::binary);
            filefmt::writeHeader(ofs, hdr);
            ofs.write((char*)salt.data(), salt.size());
            ofs.write((char*)iv.data(), iv.size());
            ofs.write((char*)tag.data(), tag.size());
            ofs.write((char*)treeBlob.data(), treeBlob.size());
            ofs.write((char*)cipher.data(), cipher.size()); // 나중에 복호화를 위한 정보들을 저장
            if (emitter) emit emitter->logMessage("파일 작성 완료...");
        }
        else        /* ------------- 복호 + 해제 ------------- */
        {
            if (emitter) emit emitter->logMessage("파일 읽는 중...");
            std::ifstream ifs(inPath, std::ios::binary);
            auto hdr = filefmt::readHeader(ifs);
            if (std::array<char, 4>(hdr.magic) != filefmt::MAGIC)
                throw std::runtime_error("bad magic");
            if (emitter) emit emitter->logMessage("파일 읽기 완료...");

            Bytes salt(hdr.salt_len); ifs.read((char*)salt.data(), salt.size());
            Bytes iv(hdr.iv_len); ifs.read((char*)iv.data(), iv.size());
            Bytes tag(hdr.tag_len); ifs.read((char*)tag.data(), tag.size());
            Bytes treeBlob(hdr.tree_len); ifs.read((char*)treeBlob.data(), treeBlob.size());
            Bytes cipher(hdr.data_len); ifs.read((char*)cipher.data(), cipher.size()); //저장한 정보들을 읽음

            /* AES-GCM 복호화 */
            Bytes encoded;
            if (emitter) emit emitter->logMessage("파일 복호화 중...");
            if (!crypto::AesGcm::decrypt(cipher, pw, salt, iv, tag, encoded)) {
                throw std::runtime_error("decrypt failed");
                if (emitter) emit emitter->logMessage("파일 복호화 실패...");
            }
            if (emitter) emit emitter->logMessage("파일 복호화 성공...");

            /* 허프만 해제 */
            huffman::Codec codec;
            if (emitter) emit emitter->logMessage("파일 압축 해제 중...");
            codec.deserializeTree(treeBlob);
            Bytes plain = codec.decode(encoded);
            if (emitter) emit emitter->logMessage("파일 압축 해제 완료...");

            /* 결과 저장 */
            if (emitter) emit emitter->logMessage("파일 작성 중...");
            writeFile(outPath, plain, progress);
            if (emitter) emit emitter->logMessage("파일 작성 완료...");
        }
        return true;
    }
    catch (const std::exception& e)
    {
        std::cerr << "hufcrypt::process: " << e.what() << '\n';
        return false;
    }
}