/* <!-- copyright */
/*
 * aria2 - The high speed download utility
 *
 * Copyright (C) 2006 Tatsuhiro Tsujikawa
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */
/* copyright --> */
#ifndef D_AUTH_CONFIG_FACTORY_H
#define D_AUTH_CONFIG_FACTORY_H

#include "common.h"

#include <string>
#include <set>
#include <memory>

#include "AuthConfig.h"
#include "SingletonHolder.h"
#include "a2functional.h"

namespace aria2 {

class Option;
class Netrc;
class AuthConfig;
class Request;
class AuthResolver;

class AuthCred {
public:
  std::string user_;
  std::string password_;
  std::string host_;
  uint16_t port_;
  std::string path_;
  bool activated_;
  std::unique_ptr<DigestAuthParams> digestAuthParams_;

  AuthCred(std::string user, std::string password, std::string host,
            uint16_t port, std::string path, bool activated = false);
  AuthCred(std::string user, std::string password, std::string host,
            uint16_t port, std::string path, std::unique_ptr<DigestAuthParams> digestAuthParams, bool activated = false);

  void upgradeToDigest(std::unique_ptr<DigestAuthParams> digestAuthParams) {
    digestAuthParams_ = std::move(digestAuthParams);
  }

  const std::unique_ptr<DigestAuthParams>& getDigestAuthParams() const {
    return digestAuthParams_;
  }

  bool isDigest() { return digestAuthParams_ != nullptr; };

  void activate();

  bool isActivated() const;

  bool operator==(const AuthCred& cred) const;

  bool operator<(const AuthCred& cred) const;
};

class AuthConfigFactory {
public:
  typedef std::set<std::unique_ptr<AuthCred>,
                   DerefLess<std::unique_ptr<AuthCred>>>
      BasicCredSet;

private:
  std::unique_ptr<Netrc> netrc_;

  std::unique_ptr<AuthResolver> createHttpAuthResolver(const Option* op) const;

  std::unique_ptr<AuthResolver> createFtpAuthResolver(const Option* op) const;

  BasicCredSet authCreds_;

public:
  AuthConfigFactory();

  ~AuthConfigFactory();

  // Creates AuthConfig object for request. Following option values
  // are used in this method: PREF_HTTP_USER, PREF_HTTP_PASSWD,
  // PREF_FTP_USER, PREF_FTP_PASSWD, PREF_NO_NETRC and
  // PREF_HTTP_AUTH_CHALLENGE.
  std::unique_ptr<AuthConfig>
  createAuthConfig(const std::shared_ptr<Request>& request, const Option* op);

  void setNetrc(std::unique_ptr<Netrc> netrc);

  // Find a AuthCred using findAuthCred() and activate it then
  // return true.  If matching AuthCred is not found, AuthConfig
  // object is created using createHttpAuthResolver and op.  If it is
  // null, then returns false. Otherwise new AuthCred is created
  // using this AuthConfig object with given host and path "/" and
  // returns true.
  bool activateAuthCred(const std::string& host, uint16_t port,
                         const std::string& path, const Option* op);
  bool activateAuthCred(const std::string& host, uint16_t port,
                         const std::string& path, const Option* op,
                         std::unique_ptr<DigestAuthParams> digestAuthParams);

  // Find a AuthCred using host, port and path and return the
  // iterator pointing to it. If not found, then return
  // authCreds_.end().
  BasicCredSet::iterator findAuthCred(const std::string& host, uint16_t port,
                                       const std::string& path);

  // If the same AuthCred is already added, then it is replaced with
  // given basicCred. Otherwise, insert given basicCred to
  // authCreds_.
  //
  // Made public for unit test.
  void updateAuthCred(std::unique_ptr<AuthCred> basicCred);
};

} // namespace aria2

#endif // D_AUTH_CONFIG_FACTORY_H
