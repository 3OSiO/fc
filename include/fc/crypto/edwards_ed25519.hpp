#pragma once
#include <fc/crypto/common.hpp>
#include <fc/crypto/sha256.hpp>
#include <fc/crypto/sha512.hpp>
#include <fc/fwd.hpp>
#include <fc/array.hpp>
#include <fc/io/raw_fwd.hpp>

namespace fc { namespace crypto { namespace ed25519 {

   namespace detail {
      class public_key_impl;
      class private_key_impl;
   }

   typedef fc::array<unsigned char,32> public_key_data;
   typedef sha256                      private_key_secret;
   typedef fc::array<unsigned char,96> compact_signature;

   class public_key {
   public:
      public_key();
      public_key(public_key&& k);
      public_key(const public_key& k);
      ~public_key();
      public_key_data serialize() const;

      operator public_key_data() const { return serialize(); }

      public_key(const public_key_data& v);
      public_key(const compact_signature& c, const fc::sha256& digest, bool check_canonical = true);

      bool valid() const;

      public_key& operator=(public_key&& pk);
      public_key& operator=(const public_key& pk);

      inline friend bool operator==(const public_key& a, const public_key& b) {
         return a.serialize() == b.serialize();
      }

      inline friend bool operator!=(const public_key& a, const public_key& b) {
         return a.serialize() != b.serialize();
      }

      std::string to_base58() const;
      static public_key from_base(const std::string& b58);

   private:
      friend class private_key;
      fc::fwd<detail::public_key_impl,32> my;
   };

   class private_key {
   public:
      private_key();
      private_key(private_key&& pk);
      private_key(const private_key& pk);
      ~private_key();

      private_key& operator=(private_key&& pk);
      private_key& operator=(const private_key& pk);

      static private_key generate();
      static private_key regenerate(const fc::sha256& secret);

      private_key_secret get_secret() const;

      operator private_key_secret() const { return get_secret(); }

      fc::sha512 get_shared_secret(const public_key& pub) const;

      compact_signature sign_compact(const fc::sha256& digest) const;

      public_key get_public_key() const;

      inline friend bool operator==(const private_key& a, const private_key& b) {
         return a.get_secret() == b.get_secret();
      }
      inline friend bool operator!=(const private_key& a, const private_key& b) {
         return a.get_secret() != b.get_secret();
      }
      inline friend bool operator<(const private_key& a, const private_key& b) {
         return a.get_secret() < b.get_secret();
      }

   private:
      fc::fwd<detail::private_key_impl,64> my;
   };

   struct public_key_shim : public crypto::shim<public_key_data> {
      using crypto::shim<public_key_data>::shim;

      bool valid() const {
         return public_key(_data).valid();
      }
   };

   struct signature_shim : public crypto::shim<compact_signature> {
      using crypto::shim<compact_signature>::shim;
      using public_key_type = public_key_shim;

      public_key_type recover(const sha256& digest, bool check_canonical) const {
         return public_key_type(public_key(_data, digest, check_canonical).serialize());
      }
   };

   struct private_key_shim : public crypto::shim<private_key_secret> {
      using crypto::shim<private_key_secret>::shim;
      using public_key_type = public_key_shim;
      using signature_type = signature_shim;

      signature_type sign(const sha256& digest, bool require_canonical = true) const {
         return signature_type(private_key::regenerate(_data).sign_compact(digest));
      }

      public_key_type get_public_key() const {
         return public_key_type(private_key::regenerate(_data).get_public_key().serialize());
      }

      sha512 generate_shared_secret(const public_key_type& pub_key) const {
         return private_key::regenerate(_data).get_shared_secret(public_key(pub_key.serialize()));
      }

      static private_key_shim generate() {
         return private_key_shim(private_key::generate().get_secret());
      }
   };

} } /// namespace fc::crypto::ed25519

void to_variant(const crypto::ed25519::private_key& var, variant& vo);
void from_variant(const variant& var, crypto::ed25519::private_key& vo);
void to_variant(const crypto::ed25519::public_key& var, variant& vo);
void from_variant(const variant& var, crypto::ed25519::public_key& vo);

namespace raw {
   template<typename Stream>
   void unpack(Stream& s, fc::crypto::ed25519::public_key& pk) {
      crypto::ed25519::public_key_data ser;
      fc::raw::unpack(s, ser);
      pk = fc::crypto::ed25519::public_key(ser);
   }

   template<typename Stream>
   void pack(Stream& s, const fc::crypto::ed25519::public_key& pk) {
      fc::raw::pack(s, pk.serialize());
   }

   template<typename Stream>
   void unpack(Stream& s, fc::crypto::ed25519::private_key& pk) {
      fc::sha256 sec;
      unpack(s, sec);
      pk = crypto::ed25519::private_key::regenerate(sec);
   }

   template<typename Stream>
   void pack(Stream& s, const fc::crypto::ed25519::private_key& pk) {
      fc::raw::pack(s, pk.get_secret());
   }
}

} /// namespace fc

#include <fc/reflect/reflect.hpp>

FC_REFLECT_TYPENAME(fc::crypto::ed25519::private_key)
FC_REFLECT_TYPENAME(fc::crypto::ed25519::public_key)
FC_REFLECT_DERIVED(fc::crypto::ed25519::public_key_shim, (fc::crypto::shim<fc::crypto::ed25519::public_key_data>), BOOST_PP_SEQ_NIL)
FC_REFLECT_DERIVED(fc::crypto::ed25519::signature_shim, (fc::crypto::shim<fc::crypto::ed25519::compact_signature>), BOOST_PP_SEQ_NIL)
FC_REFLECT_DERIVED(fc::crypto::ed25519::private_key_shim, (fc::crypto::shim<fc::crypto::ed25519::private_key_secret>), BOOST_PP_SEQ_NIL)
