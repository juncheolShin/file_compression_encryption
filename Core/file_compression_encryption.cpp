// hufcrypt.cpp  —  Huffman compression + AES‑256‑GCM encryption (and reverse)
// Usage :
//   Compress + Encrypt   : ./hufcrypt enc <input_file> <output_file> <password>
//   Decrypt + Decompress : ./hufcrypt dec <input_file> <output_file> <password>
// ---------------------------------------------------------------
#include "file_compression_encryption.h"
#define DBG(expr) do { std::cerr << "[DBG] " #expr " = " << (expr) << '\n'; } while(0)

using Byte = unsigned char;
using Bytes = std::vector<Byte>;

namespace crypto {
    constexpr size_t KEY_LEN = 32; // 256‑bit
    constexpr size_t IV_LEN = 12; // GCM 권장 96‑bit
    constexpr size_t TAG_LEN = 16; // GCM 태그
    constexpr size_t SALT_LEN = 16;

    class AesGcm {
    public:
        static bool encrypt(const Bytes& plaintext,
            const std::string& password,
            Bytes& ciphertext, Bytes& salt, Bytes& iv, Bytes& tag);

        static bool decrypt(const Bytes& ciphertext,
            const std::string& password,
            const Bytes& salt, const Bytes& iv, const Bytes& tag,
            Bytes& plaintext);
    private:
        static Bytes deriveKey(const std::string& password, const Bytes& salt);
    };

    Bytes AesGcm::deriveKey(const std::string& password, const Bytes& salt) {
        Bytes key(KEY_LEN);
        PKCS5_PBKDF2_HMAC(password.c_str(), password.size(),
            salt.data(), salt.size(),
            150000, EVP_sha256(), KEY_LEN, key.data());
        return key;
    }

    bool AesGcm::encrypt(const Bytes& plaintext, const std::string& password,
        Bytes& ciphertext, Bytes& salt, Bytes& iv, Bytes& tag) {
        salt.resize(SALT_LEN);
        RAND_bytes(salt.data(), SALT_LEN);
        iv.resize(IV_LEN);
        RAND_bytes(iv.data(), IV_LEN);
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
        ciphertext.resize(out_len);

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

// ───────────────────── Huffman ─────────────────────
namespace huffman {
    class Node {
    public:
        Byte  byte;
        uint64_t freq;
        Node* left = nullptr;
        Node* right = nullptr;
        Node(Byte b, uint64_t f) : byte(b), freq(f) {}
        Node(Node* l, Node* r) : byte(0), freq(l->freq + r->freq), left(l), right(r) {}
        Node() : byte(0), freq(0) {};
        bool isLeaf() const { return !left && !right; }
    };

    struct NodeCmp {
        bool operator()(Node* a, Node* b) const { return a->freq > b->freq; }
    };

    class Codec {
    public:
        void build(const Bytes& data);
        Bytes encode(const Bytes& data) const;
        Bytes decode(const Bytes& bitstream) const;
        Bytes serializeTree() const;               // 리프 테이블 헤더용
        void   deserializeTree(const Bytes& blob); // 복구
    private:
        void buildCode(Node* node, std::string cur);
        void freeTree(Node* node);
        Node* root = nullptr;
        std::array<std::string, 256> table; // byte → code
    };

    void Codec::build(const Bytes& data) {
        if (data.empty()) {                     
            root = nullptr;
            table.fill("");
            return;
        }
        std::array<uint64_t, 256> freq{};
        for (Byte b : data) ++freq[b];
        std::priority_queue<Node*, std::vector<Node*>, NodeCmp> pq;
        for (int i = 0; i < 256; ++i) if (freq[i]) pq.push(new Node((Byte)i, freq[i]));
        if (pq.size() == 1) pq.push(new Node(0, 1)); // 단일 문자 예외
        while (pq.size() > 1) {
            Node* a = pq.top(); pq.pop();
            Node* b = pq.top(); pq.pop();
            pq.push(new Node(a, b));
        }
        root = pq.top();
        buildCode(root, "");
    }

    void Codec::buildCode(Node* node, std::string cur) {
        if (node->isLeaf()) {
            table[node->byte] = cur.empty() ? "0" : cur;
            return;
        }
        buildCode(node->left, cur + '0');
        buildCode(node->right, cur + '1');
    }

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
            // pack bits into bytes
            std::string padded = code;
            size_t pad = (8 - padded.size() % 8) % 8;
            padded.append(pad, '0');
            for (size_t i = 0; i < padded.size(); i += 8) {
                Byte v = 0;
                for (int j = 0; j < 8; ++j) if (padded[i + j] == '1') v |= 1 << (7 - j);
                blob.push_back(v);
            }
        }
        return blob;
    }

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

// ───────────────────── 파일 IO / 헤더 ─────────────────────
namespace filefmt {
    const std::array<char, 4> MAGIC = { 'H','U','F','1' }; // 4
    enum Alg : Byte { ALG_AES_GCM = 1 };

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

    void writeHeader(std::ofstream& ofs, const Header& h) {
        ofs.write(reinterpret_cast<const char*>(&h), sizeof(Header));
    }
    Header readHeader(std::ifstream& ifs) {
        Header h; ifs.read(reinterpret_cast<char*>(&h), sizeof(Header)); return h;
    }
} // namespace filefmt

// ───────────────────── Main workflow ─────────────────────
static Bytes readFile(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    return Bytes(std::istreambuf_iterator<char>(ifs), {});
}
static void writeFile(const std::string& path, const Bytes& data) {
    std::ofstream ofs(path, std::ios::binary); ofs.write((char*)data.data(), data.size());
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: ./hufcrypt <enc|dec> <in> <out> <password>\n";
        return 1;
    }
    std::string mode = argv[1]; std::string inF = argv[2]; std::string outF = argv[3]; std::string pw = argv[4];

    if (mode == "enc") {
        Bytes plain = readFile(inF);
        huffman::Codec codec; codec.build(plain);
        Bytes treeBlob = codec.serializeTree();
        Bytes encoded = codec.encode(plain);

        Bytes cipher, salt, iv, tag;
        if (!crypto::AesGcm::encrypt(encoded, pw, cipher, salt, iv, tag)) {
            std::cerr << "Encryption failed\n"; return 2;
        }
        filefmt::Header hdr; hdr.tree_len = treeBlob.size(); hdr.data_len = cipher.size();
        std::ofstream ofs(outF, std::ios::binary);
        filefmt::writeHeader(ofs, hdr);
        ofs.write((char*)salt.data(), salt.size());
        ofs.write((char*)iv.data(), iv.size());
        ofs.write((char*)tag.data(), tag.size());
        ofs.write((char*)treeBlob.data(), treeBlob.size());
        ofs.write((char*)cipher.data(), cipher.size());
        std::cout << "OK: saved " << outF << "\n";
    }
    else if (mode == "dec") {
        std::ifstream ifs(inF, std::ios::binary);
        auto hdr = filefmt::readHeader(ifs);
        if (std::array<char, 4>(hdr.magic) != filefmt::MAGIC) { std::cerr << "Bad magic"; return 3; }

        Bytes salt(hdr.salt_len); ifs.read((char*)salt.data(), salt.size());
        Bytes iv(hdr.iv_len); ifs.read((char*)iv.data(), iv.size());
        Bytes tag(hdr.tag_len); ifs.read((char*)tag.data(), tag.size());
        Bytes treeBlob(hdr.tree_len); ifs.read((char*)treeBlob.data(), treeBlob.size());
        Bytes cipher(hdr.data_len);    ifs.read((char*)cipher.data(), cipher.size());

        // ── dec 모드 읽기 직후 ───────────────────────────────
        DBG(hdr.tree_len); DBG(hdr.data_len);
        DBG(salt.size()); DBG(iv.size()); DBG(tag.size());
        DBG(ifs.good());  // 파일 스트림 상태

        Bytes encoded;
        if (!crypto::AesGcm::decrypt(cipher, pw, salt, iv, tag, encoded)) {
            std::cerr << "Decryption failed (bad password/modified)\n"; 
            ERR_print_errors_fp(stderr);
            return 4;
        }
        huffman::Codec codec; codec.deserializeTree(treeBlob);
        Bytes plain = codec.decode(encoded);
        writeFile(outF, plain);
        std::cout << "OK: restored " << outF << "\n";
    }
    else {
        std::cerr << "Unknown mode\n"; return 5;
    }
    return 0;
}
