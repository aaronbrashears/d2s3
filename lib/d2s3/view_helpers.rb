require 'base64'
require 'addressable/template'

module D2S3
  module ViewHelpers
    include D2S3::Signature

    def s3_http_upload_tag(options = {})
      bucket          = D2S3::S3Config.bucket
      access_key_id   = D2S3::S3Config.access_key_id
      key             = options[:key] || ''
      filename        = options[:filename] || '${filename}'
      content_type    = options[:content_type] || '' # Defaults to binary/octet-stream if blank
      redirect        = options[:redirect] || '/'
      acl             = options[:acl] || 'public-read'
      expiration_date = (options[:expiration_date] || 10.hours).from_now.utc.strftime('%Y-%m-%dT%H:%M:%S.000Z')
      max_filesize    = options[:max_filesize] || 1.megabyte
      min_filesize    = options[:min_filesize] || 1.byte
      submit_button   = options[:submit_button] || '<input type="submit" value="Upload">'
      protocol        = options[:secure] ? 'https' : 'http'
      cname           = options[:cname] || false

      # CNAME cannot use https and bucket mut be the same as the
      # Host headeraccording to S3 documentation.
      host = cname ? host = "#{bucket}" : "#{bucket}.s3.amazonaws.com"
      file_key = "#{key}/#{filename}"
      upload_uri = "#{protocol}://#{host}/#{file_key}"

      options[:form] ||= {}
      options[:form][:id] ||= 'upload-form'
      options[:form][:class] ||= 'upload-form'

      # Process they query string for the redirect url.
      replace = {
        :upload_uri => upload_uri,
        :host => host,
        :bucket => bucket,
        :key => file_key,
      }
      redirect_str = Addressable::URI.unencode(redirect)
      redirect_template = Addressable::Template.new(redirect_str)
      redirect_uri = redirect_template.expand(replace)

      policy = Base64.encode64(
        "{'expiration': '#{expiration_date}',
          'conditions': [
            {'bucket': '#{bucket}'},
            ['starts-with', '$key', '#{key}'],
            {'acl': '#{acl}'},
            {'success_action_redirect': '#{redirect_uri}'},
            ['starts-with', '$Content-Type', '#{content_type}'],
            ['content-length-range', #{min_filesize}, #{max_filesize}]
          ]
        }").gsub(/\n|\r/, '')

        signature = b64_hmac_sha1(D2S3::S3Config.secret_access_key, policy)
        out = ""
        out << %(
          <form action="#{protocol}://#{host}/" method="post" enctype="multipart/form-data" id="#{options[:form][:id]}" class="#{options[:form][:class]}" style="#{options[:form][:style]}" \>
          <input type="hidden" name="key" value="#{file_key}" \>
          <input type="hidden" name="AWSAccessKeyId" value="#{access_key_id}" \>
          <input type="hidden" name="acl" value="#{acl}" \>
          <input type="hidden" name="success_action_redirect" value="#{redirect_uri}" \>
          <input type="hidden" name="policy" value="#{policy}" \>
          <input type="hidden" name="signature" value="#{signature}" \>
          <input type="hidden" name="Content-Type" value="#{content_type}" \>
          <input name="file" type="file" \>#{submit_button}
          </form>
        )
    end
  end
end

ActionView::Base.send(:include, D2S3::ViewHelpers)
