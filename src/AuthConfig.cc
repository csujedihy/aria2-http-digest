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
#include "AuthConfig.h"

#include <ostream>

#include "LogFactory.h"
#include "util.h"
#include "base64.h"
#include "MessageDigest.h"
#include "a2functional.h"

namespace aria2 {

AuthConfig::AuthConfig() {}

AuthConfig::AuthConfig(std::string user, std::string password)
    : user_(std::move(user)), password_(std::move(password))
{
  authScheme_ = AUTH_BASIC;
}

AuthConfig::AuthConfig(std::string user, std::string password, std::string path, std::string method, const std::unique_ptr<DigestAuthParams>& digestAuthParams)
    : user_(std::move(user)), password_(std::move(password))
{
  authScheme_ = AUTH_DIGEST;
  auto digest = MessageDigest::create("md5");
  const auto rawH1 = user_ + ":" + digestAuthParams->realm + ":" + password_;
  const auto rawH2 = method + ":" + path;
  digest->update(rawH1.c_str(), rawH1.length());
  std::string H1 = util::toHex(digest->digest());
  digest->reset();
  digest->update(rawH2.c_str(), rawH2.length());
  std::string H2 = util::toHex(digest->digest());
  const auto rawResponse = H1 + ":" + digestAuthParams->serverNonce + ":00000001:0a4f113b:" + digestAuthParams->qop + ":" + H2;
  digest->reset();
  digest->update(rawResponse.c_str(), rawResponse.length());
  std::string response = util::toHex(digest->digest());
  digest_ = " username=\"" + user_ + "\", realm=\"" + digestAuthParams->realm + "\", nonce=\"" + digestAuthParams->serverNonce + "\", uri=\"" + path + "\", algorithm=" + digestAuthParams->algorithm + ", response=\"" + response + "\", qop=" + digestAuthParams->qop + " , nc=00000001, cnonce=\"0a4f113b\"";
  A2_LOG_INFO("Created HTTP digest");
}

AuthConfig::~AuthConfig() = default;

std::string AuthConfig::getAuthText() const
{
  if (authScheme_ == AUTH_BASIC) {
    std::string s = user_;
    s += ":";
    s += password_;
    return "Basic " + base64::encode(std::begin(s), std::end(s));
  } else if (authScheme_ == AUTH_DIGEST) {
    return "Digest " + digest_;
  } else {
    return nullptr;
  }
}

std::unique_ptr<AuthConfig> AuthConfig::create(std::string user,
                                               std::string password)
{
  if (user.empty()) {
    return nullptr;
  }
  else {
    return make_unique<AuthConfig>(std::move(user), std::move(password));
  }
}

std::unique_ptr<AuthConfig> AuthConfig::create(std::string user,
                                               std::string password,
                                               std::string path, // dir + file path
                                               std::string method,
                                               const std::unique_ptr<DigestAuthParams>& digestAuthParams)
{
  if (user.empty()) {
    return nullptr;
  }
  else {
    return make_unique<AuthConfig>(std::move(user), std::move(password), path, method, digestAuthParams);
  }
}

std::ostream& operator<<(std::ostream& o,
                         const std::shared_ptr<AuthConfig>& authConfig)
{
  o << authConfig->getAuthText();
  return o;
}

} // namespace aria2
