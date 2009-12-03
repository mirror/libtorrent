/*

Copyright (c) 2006, Arvid Norberg
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the distribution.
    * Neither the name of the author nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

*/

#ifndef TORRENT_SESSION_HPP_INCLUDED
#define TORRENT_SESSION_HPP_INCLUDED

#include <algorithm>
#include <vector>

#ifdef _MSC_VER
#pragma warning(push, 1)
#endif

#include <boost/limits.hpp>

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include "libtorrent/config.hpp"
#include "libtorrent/torrent_handle.hpp"
#include "libtorrent/entry.hpp"
#include "libtorrent/session_status.hpp"
#include "libtorrent/version.hpp"
#include "libtorrent/fingerprint.hpp"
#include "libtorrent/disk_io_thread.hpp"
#include "libtorrent/peer_id.hpp"
#include "libtorrent/alert.hpp" // alert::error_notification
#include "libtorrent/add_torrent_params.hpp"

#include "libtorrent/storage.hpp"
#include <boost/preprocessor/cat.hpp>


#ifdef _MSC_VER
#	include <eh.h>
#endif

namespace libtorrent
{
	struct torrent_plugin;
	class torrent;
	class ip_filter;
	class port_filter;
	class connection_queue;
	class natpmp;
	class upnp;
	class alert;

	// this is used to create linker errors when trying to link to
	// a library with a conflicting build configuration than the application
#ifdef TORRENT_DEBUG
#define G _release
#else
#define G _debug
#endif

#ifdef TORRENT_USE_OPENSSL
#define S _ssl
#else
#define S _nossl
#endif

#ifdef TORRENT_DISABLE_DHT
#define D _nodht
#else
#define D _dht
#endif

#ifdef TORRENT_DISABLE_POOL_ALLOCATOR
#define P _nopoolalloc
#else
#define P _poolalloc
#endif

#define TORRENT_LINK_TEST_PREFIX libtorrent_build_config
#define TORRENT_LINK_TEST_NAME BOOST_PP_CAT(TORRENT_LINK_TEST_PREFIX, BOOST_PP_CAT(P, BOOST_PP_CAT(D, BOOST_PP_CAT(S, G))))
#undef P
#undef D
#undef S
#undef G

	inline void test_link()
	{
		extern void TORRENT_LINK_TEST_NAME();
		TORRENT_LINK_TEST_NAME();
	}

	session_settings min_memory_usage();
	session_settings high_performance_seed();

	namespace aux
	{
		// workaround for microsofts
		// hardware exceptions that makes
		// it hard to debug stuff
#ifdef _MSC_VER
		struct eh_initializer
		{
			eh_initializer()
			{
				::_set_se_translator(straight_to_debugger);
			}

			static void straight_to_debugger(unsigned int, _EXCEPTION_POINTERS*)
			{ throw; }
		};
#else
		struct eh_initializer {};
#endif
		struct session_impl;
	}

	class TORRENT_EXPORT session_proxy
	{
		friend class session;
	public:
		session_proxy() {}
	private:
		session_proxy(boost::shared_ptr<aux::session_impl> impl)
			: m_impl(impl) {}
		boost::shared_ptr<aux::session_impl> m_impl;
	};

	class TORRENT_EXPORT session: public boost::noncopyable, aux::eh_initializer
	{
	public:

		session(fingerprint const& print = fingerprint("LT"
			, LIBTORRENT_VERSION_MAJOR, LIBTORRENT_VERSION_MINOR, 0, 0)
			, int flags = start_default_features | add_default_plugins
			, int alert_mask = alert::error_notification
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING || defined TORRENT_ERROR_LOGGING
			, std::string logpath = "."
#endif
				);
		session(
			fingerprint const& print
			, std::pair<int, int> listen_port_range
			, char const* listen_interface = "0.0.0.0"
			, int flags = start_default_features | add_default_plugins
			, int alert_mask = alert::error_notification
#if defined TORRENT_VERBOSE_LOGGING || defined TORRENT_LOGGING || defined TORRENT_ERROR_LOGGING
			, std::string logpath = "."
#endif
			);
			
		~session();

		void save_state(entry& e) const;
		void load_state(lazy_entry const& e);

		// returns a list of all torrents in this session
		std::vector<torrent_handle> get_torrents() const;
		
		io_service& get_io_service();

		// returns an invalid handle in case the torrent doesn't exist
		torrent_handle find_torrent(sha1_hash const& info_hash) const;

		// all torrent_handles must be destructed before the session is destructed!
		torrent_handle add_torrent(add_torrent_params const& params);
		torrent_handle add_torrent(add_torrent_params const& params, error_code& ec);
		
#ifndef TORRENT_NO_DEPRECATE
		// deprecated in 0.14
		TORRENT_DEPRECATED_PREFIX
		torrent_handle add_torrent(
			torrent_info const& ti
			, std::string const& save_path
			, entry const& resume_data = entry()
			, storage_mode_t storage_mode = storage_mode_sparse
			, bool paused = false
			, storage_constructor_type sc = default_storage_constructor) TORRENT_DEPRECATED;

		// deprecated in 0.14
		TORRENT_DEPRECATED_PREFIX
		torrent_handle add_torrent(
			boost::intrusive_ptr<torrent_info> ti
			, std::string const& save_path
			, entry const& resume_data = entry()
			, storage_mode_t storage_mode = storage_mode_sparse
			, bool paused = false
			, storage_constructor_type sc = default_storage_constructor
			, void* userdata = 0) TORRENT_DEPRECATED;

		// deprecated in 0.14
		TORRENT_DEPRECATED_PREFIX
		torrent_handle add_torrent(
			char const* tracker_url
			, sha1_hash const& info_hash
			, char const* name
			, std::string const& save_path
			, entry const& resume_data = entry()
			, storage_mode_t storage_mode = storage_mode_sparse
			, bool paused = false
			, storage_constructor_type sc = default_storage_constructor
			, void* userdata = 0) TORRENT_DEPRECATED;
#endif

		session_proxy abort() { return session_proxy(m_impl); }

		void pause();
		void resume();
		bool is_paused() const;

		session_status status() const;
		cache_status get_cache_status() const;

		void get_cache_info(sha1_hash const& ih
			, std::vector<cached_piece_info>& ret) const;

#ifndef TORRENT_DISABLE_DHT
		void start_dht(entry const& startup_state = entry());
		void stop_dht();
		void set_dht_settings(dht_settings const& settings);
		entry dht_state() const;
		void add_dht_node(std::pair<std::string, int> const& node);
		void add_dht_router(std::pair<std::string, int> const& node);
		bool is_dht_running() const;
#endif

#ifndef TORRENT_DISABLE_ENCRYPTION
		void set_pe_settings(pe_settings const& settings);
		pe_settings const& get_pe_settings() const;
#endif

#ifndef TORRENT_DISABLE_EXTENSIONS
		void add_extension(boost::function<boost::shared_ptr<torrent_plugin>(torrent*, void*)> ext);
#endif

#ifndef TORRENT_DISABLE_GEO_IP
		int as_for_ip(address const& addr);
		bool load_asnum_db(char const* file);
		bool load_country_db(char const* file);
#if TORRENT_USE_WSTRING
		bool load_country_db(wchar_t const* file);
		bool load_asnum_db(wchar_t const* file);
#endif
#endif

		void load_state(entry const& ses_state);
		entry state() const;

		void set_ip_filter(ip_filter const& f);
		ip_filter const& get_ip_filter() const;
		
		void set_port_filter(port_filter const& f);
		void set_peer_id(peer_id const& pid);
		void set_key(int key);
		peer_id id() const;

		bool is_listening() const;

		// if the listen port failed in some way
		// you can retry to listen on another port-
		// range with this function. If the listener
		// succeeded and is currently listening,
		// a call to this function will shut down the
		// listen port and reopen it using these new
		// properties (the given interface and port range).
		// As usual, if the interface is left as 0
		// this function will return false on failure.
		// If it fails, it will also generate alerts describing
		// the error. It will return true on success.
		bool listen_on(
			std::pair<int, int> const& port_range
			, const char* net_interface = 0);

		// returns the port we ended up listening on
		unsigned short listen_port() const;

		// Get the number of uploads.
		int num_uploads() const;

		// Get the number of connections. This number also contains the
		// number of half open connections.
		int num_connections() const;

		enum options_t
		{
			none = 0,
			delete_files = 1
		};

		enum session_flags_t
		{
			add_default_plugins = 1,
			start_default_features = 2
		};

		void remove_torrent(const torrent_handle& h, int options = none);

		void set_settings(session_settings const& s);
		session_settings const& settings();

		void set_peer_proxy(proxy_settings const& s);
		void set_web_seed_proxy(proxy_settings const& s);
		void set_tracker_proxy(proxy_settings const& s);

		proxy_settings const& peer_proxy() const;
		proxy_settings const& web_seed_proxy() const;
		proxy_settings const& tracker_proxy() const;

#ifndef TORRENT_DISABLE_DHT
		void set_dht_proxy(proxy_settings const& s);
		proxy_settings const& dht_proxy() const;
#endif

#if TORRENT_USE_I2P
		void set_i2p_proxy(proxy_settings const& s);
		proxy_settings const& i2p_proxy() const;
#endif

		int upload_rate_limit() const;
		int download_rate_limit() const;
		int local_upload_rate_limit() const;
		int local_download_rate_limit() const;
		int max_half_open_connections() const;

		void set_local_upload_rate_limit(int bytes_per_second);
		void set_local_download_rate_limit(int bytes_per_second);
		void set_upload_rate_limit(int bytes_per_second);
		void set_download_rate_limit(int bytes_per_second);
		void set_max_uploads(int limit);
		void set_max_connections(int limit);
		void set_max_half_open_connections(int limit);

		int max_connections() const;
		int max_uploads() const;

		std::auto_ptr<alert> pop_alert();
#ifndef TORRENT_NO_DEPRECATE
		TORRENT_DEPRECATED_PREFIX
		void set_severity_level(alert::severity_t s) TORRENT_DEPRECATED;
#endif
		void set_alert_mask(int m);
		size_t set_alert_queue_size_limit(size_t queue_size_limit_);

		alert const* wait_for_alert(time_duration max_wait);
		void set_alert_dispatch(boost::function<void(alert const&)> const& fun);

		connection_queue& get_connection_queue();

		// starts/stops UPnP, NATPMP or LSD port mappers
		// they are stopped by default
		void start_lsd();
		natpmp* start_natpmp();
		upnp* start_upnp();

		void stop_lsd();
		void stop_natpmp();
		void stop_upnp();
		
	private:

		// data shared between the main thread
		// and the working thread
		boost::shared_ptr<aux::session_impl> m_impl;
	};

}

#endif // TORRENT_SESSION_HPP_INCLUDED

