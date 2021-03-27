#include <fc/crypto/edwards_ed25519.hpp>
#include <fc/crypto/base58.hpp>
#include <fc/exception/exception.hpp>
#include <fc/fwd_impl.hpp>
#include <sodium.h>

namespace fc { namespace crypto { namespace ed25519 {

   namespace detail {

      class public_key_impl {
      public:
         public_key_impl() {
            if (sodium_init() == -1) {
               FC_THROW_EXCEPTION(exception, "Failed to initialize libsodium");
            }
         }

         public_key_impl(const public_key_impl& cpy) : _key(cpy._key) {
            if (sodium_init() == -1) {
               FC_THROW_EXCEPTION(exception, "Failed to initialize libsodium");
            }
         }

         fc::array<unsigned char, crypto_sign_PUBLICKEYBYTES> _key;
      };

      class private_key_impl {
      public:
         private_key_impl() {
            if (sodium_init() == -1) {
               FC_THROW_EXCEPTION(exception, "Failed to initialize libsodium");
            }
         }

         private_key_impl(const private_key_impl& cpy) : _key(cpy._key) {
            if (sodium_init() == -1) {
               FC_THROW_EXCEPTION(exception, "Failed to initialize libsodium");
            }
         }

         fc::array<unsigned char, crypto_sign_SECRETKEYBYTES> _key;
      };
   }

   static const public_key_data empty_pub{};
   static const fc::array<unsigned char, crypto_sign_SECRETKEYBYTES> empty_priv{};

   public_key::public_key() {}

   public_key::public_key(const public_key& pk) : my(pk.my) {}

   public_key::public_key(public_key&& pk) : my(fc::move(pk.my)) {}

   public_key::~public_key() {}

   public_key& public_key::operator=(const public_key& pk) {
      my = pk.my;
      return *this;
   }

   public_key& public_key::operator=(public_key&& pk) {
      my = pk.my;
      return *this;
   }

   public_key::public_key(const public_key_data& data) {
      my->_key = data;
   }

   bool public_key::valid() const {
      return my->_key != empty_pub;
   }

   std::string public_key::to_base58() const {
      FC_ASSERT( my->_key != empty_pub );
      return fc::to_base58(reinterpret_cast<const char*>(my->_key.data), my->_key.size(), fc::yield_function_t()); 
   }

   public_key_data public_key::serialize() const {
      FC_ASSERT( my->_key != empty_pub );
      return my->_key;
   }

   public_key::public_key(const compact_signature& c, const fc::sha256& digest, bool check_canonical) {
      FC_ASSERT( !crypto_sign_verify_detached(
         c.data,
         reinterpret_cast<const unsigned char*>(digest.data()),
         digest.data_size(),
         &c.data[crypto_sign_BYTES]
      ) );
      std::memcpy(my->_key.data, &c.data[crypto_sign_BYTES], crypto_sign_PUBLICKEYBYTES);
   }

   private_key::private_key() {}

   private_key::private_key(const private_key& pk) : my(pk.my) {}

   private_key::private_key(private_key&& pk) : my(fc::move(pk.my)) {}

   private_key::~private_key() {}

   private_key& private_key::operator=(private_key&& pk) {
      my = pk.my;
      return *this;
   }

   private_key& private_key::operator=(const private_key& pk) {
      my = pk.my;
      return *this;
   }

   private_key private_key::regenerate(const fc::sha256& secret) {
      private_key priv;
      fc::array<unsigned char, crypto_sign_PUBLICKEYBYTES>pub;
      FC_ASSERT( !crypto_sign_seed_keypair(pub.data, priv.my->_key.data, reinterpret_cast<unsigned char*>(secret.data())) );
      return priv;
   }

   fc::sha256 private_key::get_secret() const {
      fc::sha256 priv;
      std::memcpy(priv.data(), reinterpret_cast<const char*>(my->_key.data), priv.data_size());
      return priv;
   }

   private_key private_key::generate() {
      private_key priv;
      fc::array<unsigned char, crypto_sign_PUBLICKEYBYTES> pub;
      FC_ASSERT( !crypto_sign_keypair(pub.data, priv.my->_key.data) );
      return priv;
   }

   public_key private_key::get_public_key() const {
      public_key_data pub;
      std::memcpy(pub.data, &my->_key.data[32], pub.size());
      return public_key(pub);
   }

   fc::sha512 private_key::get_shared_secret(const public_key& other) const {
      FC_ASSERT( my->_key != empty_priv );
      FC_ASSERT( other.my->_key != empty_pub );
      fc::sha512 buf;
      fc::array<unsigned char, crypto_scalarmult_BYTES> q;
      FC_ASSERT( !crypto_scalarmult(q.data, my->_key.data, other.my->_key.data) );
      return fc::sha512::hash(reinterpret_cast<const char*>(q.data), crypto_scalarmult_BYTES);
   }

   compact_signature private_key::sign_compact(const fc::sha256& digest) const {
      compact_signature sig;
      unsigned long long siglen = 0;
      FC_ASSERT( !crypto_sign_detached(
         sig.data,
         &siglen,
         reinterpret_cast<const unsigned char*>(digest.data()),
         digest.data_size(),
         my->_key.data
      ) );
      std::memcpy(&sig.data[crypto_sign_BYTES], &my->_key.data[32], crypto_sign_PUBLICKEYBYTES);
      return sig;
   }

} } /// namespace fc::crypto

void to_variant(const crypto::ed25519::private_key& var, variant& vo) {
   vo = var.get_secret();
}

void from_variant(const variant& var, crypto::ed25519::private_key& vo) {
   fc::sha256 priv;
   from_variant(var, priv);
   vo = crypto::ed25519::private_key::regenerate(priv);
}

void to_variant(const crypto::ed25519::public_key& var, variant& vo) {
   vo = var.serialize();
}

void from_variant(const variant& var, crypto::ed25519::public_key& vo) {
   crypto::ed25519::public_key_data pub;
   from_variant(var, pub);
   vo = crypto::ed25519::public_key(pub);
}

} /// namespace fc
