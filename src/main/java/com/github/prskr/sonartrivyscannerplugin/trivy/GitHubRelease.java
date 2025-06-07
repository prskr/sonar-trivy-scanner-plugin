package com.github.prskr.sonartrivyscannerplugin.trivy;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.OffsetDateTime;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record GitHubRelease(
        String url,
        @JsonProperty("assets_url") String assetsUrl,
        @JsonProperty("upload_url") String uploadUrl,
        @JsonProperty("html_url") String htmlUrl,
        Long id,
        Author author,
        @JsonProperty("node_id") String nodeId,
        @JsonProperty("tag_name") String tagName,
        @JsonProperty("target_commitish") String targetCommitish,
        String name,
        Boolean draft,
        Boolean prerelease,
        @JsonProperty("created_at") OffsetDateTime createdAt,
        @JsonProperty("published_at") OffsetDateTime publishedAt,
        List<Asset> assets,
        @JsonProperty("tarball_url") String tarballUrl,
        @JsonProperty("zipball_url") String zipballUrl,
        String body,
        @JsonProperty("discussion_url") String discussionUrl
) {

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Author(
            String login,
            Long id,
            @JsonProperty("node_id") String nodeId,
            @JsonProperty("avatar_url") String avatarUrl,
            @JsonProperty("gravatar_id") String gravatarId,
            String url,
            @JsonProperty("html_url") String htmlUrl,
            @JsonProperty("followers_url") String followersUrl,
            @JsonProperty("following_url") String followingUrl,
            @JsonProperty("gists_url") String gistsUrl,
            @JsonProperty("starred_url") String starredUrl,
            @JsonProperty("subscriptions_url") String subscriptionsUrl,
            @JsonProperty("organizations_url") String organizationsUrl,
            @JsonProperty("repos_url") String reposUrl,
            @JsonProperty("events_url") String eventsUrl,
            @JsonProperty("received_events_url") String receivedEventsUrl,
            String type,
            @JsonProperty("user_view_type") String userViewType,
            @JsonProperty("site_admin") Boolean siteAdmin
    ) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Asset(
            String url,
            Long id,
            @JsonProperty("node_id") String nodeId,
            String name,
            String label,
            Uploader uploader,
            @JsonProperty("content_type") String contentType,
            String state,
            Long size,
            String digest,
            @JsonProperty("download_count") Long downloadCount,
            @JsonProperty("created_at") OffsetDateTime createdAt,
            @JsonProperty("updated_at") OffsetDateTime updatedAt,
            @JsonProperty("browser_download_url") String browserDownloadUrl
    ) {

        @JsonIgnoreProperties(ignoreUnknown = true)
        public record Uploader(
                String login,
                Long id,
                @JsonProperty("node_id") String nodeId,
                @JsonProperty("avatar_url") String avatarUrl,
                @JsonProperty("gravatar_id") String gravatarId,
                String url,
                @JsonProperty("html_url") String htmlUrl,
                @JsonProperty("followers_url") String followersUrl,
                @JsonProperty("following_url") String followingUrl,
                @JsonProperty("gists_url") String gistsUrl,
                @JsonProperty("starred_url") String starredUrl,
                @JsonProperty("subscriptions_url") String subscriptionsUrl,
                @JsonProperty("organizations_url") String organizationsUrl,
                @JsonProperty("repos_url") String reposUrl,
                @JsonProperty("events_url") String eventsUrl,
                @JsonProperty("received_events_url") String receivedEventsUrl,
                String type,
                @JsonProperty("user_view_type") String userViewType,
                @JsonProperty("site_admin") Boolean siteAdmin
        ) {}
    }
}
