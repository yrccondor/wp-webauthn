<?php
settings_errors();
// Insert CSS and JS
wp_enqueue_script('wwa_admin', plugins_url('js/admin.js',__FILE__));
wp_localize_script('wwa_admin', 'php_vars', array('ajax_url' => admin_url('admin-ajax.php'),'i18n_1' => __('正在初始化...','wwa'),'i18n_2' => __('请按照浏览器接下来的提示完成绑定...','wwa'),'i18n_3' => '<span class="success">'.__('绑定成功','wwa').'</span>','i18n_4' => '<span class="failed">'.__('绑定失败','wwa').'</span>','i18n_5' => __('你的浏览器不支持 WebAuthn','wwa'),'i18n_6' => __('正在绑定...','wwa'),'i18n_7' => __('请填写认证器名称','wwa'),'i18n_8' => __('加载失败，刷新试试？','wwa'),'i18n_9' => __('任意','wwa'),'i18n_10' => __('内置认证器','wwa'),'i18n_11' => __('外部认证器','wwa'),'i18n_12' => __('删除','wwa'),'i18n_13' => __('请按照浏览器接下来的提示进行验证...','wwa'),'i18n_14' => __('正在验证...','wwa'),'i18n_15' => '<span class="failed">'.__('验证失败','wwa').'</span>','i18n_16' => '<span class="success">'.__('验证成功，你的账户现可通过 WebAuthn 登录','wwa').'</span>','i18n_17' => __('没有已绑定的认证器','wwa'),'i18n_18' => __('确认删除验证器：','wwa'),'i18n_19' => __('正在删除...','wwa')));
wp_enqueue_style('wwa_admin', plugins_url('css/admin.css',__FILE__));
?>
<div class="wrap"><h1>WP-WebAuthn</h1>
<?php
// Only admin can change settings
if((isset($_POST['wwa_ref']) && $_POST['wwa_ref'] == 'true') && check_admin_referer('wwa_options_update') && current_user_can('edit_plugins')){
    wwa_update_option('first_choice', $_POST['first_choice']);
    wwa_update_option('website_name', $_POST['website_name']);
    wwa_update_option('website_domain', $_POST['website_domain']);
?>
<div class="notice notice-success is-dismissible">
<p><?php _e('设置已保存。', 'wwa'); ?></p>
</div>
<?php
}elseif((isset($_POST['wwa_ref']) && $_POST['wwa_ref'] == 'true') && !(check_admin_referer('wwa_options_update'))){
?>
<div class="notice notice-error is-dismissible">
<p><?php _e('更改未能保存。', 'wwa'); ?></p>
</div>
<?php }
// Only admin can change settings
if(current_user_can("edit_plugins")){ ?>
<form method="post" action="">
<?php
wp_nonce_field('wwa_options_update');
?>
<input type='hidden' name='wwa_ref' value='true'>
<table class="form-table">
<tr>
<th scope="row"><label for="first_choice"><?php _e('登录页面默认登录方式', 'wwa');?></lable></th>
<td>
<?php $wwa_v_first_choice=wwa_get_option('first_choice');?>
    <fieldset>
    <label><input type="radio" name="first_choice" value="true" <?php if($wwa_v_first_choice=='true'){?>checked="checked"<?php }?>> <?php _e('WebAuthn', 'wwa');?></label><br>
    <label><input type="radio" name="first_choice" value="false" <?php if($wwa_v_first_choice=='false'){?>checked="checked"<?php }?>> <?php _e('密码', 'wwa');?></label><br>
    <p class="description"><?php _e('由于目前 WebAuthn 还没有得到良好的浏览器支持，因此你只能选择登录页面默认显示的登录方式，而<strong>不能彻底禁用密码登录方式。</strong><br>无论你将哪种登录方式设为了默认，登录页面都将会显示一个切换按钮以便于你切换到另一种登录方式。<br>当浏览器不支持 WebAuthn 时，无论你将哪种登录方式设为了默认，密码登录方式都将被默认显示。', 'wwa');?></p>
    </fieldset>
</td>
</tr>
<tr>
<th scope="row"><label for="website_name"><?php _e('网站名称', 'wwa');?></lable></th>
<td>
    <input required name="website_name" type="text" id="website_name" value="<?php echo wwa_get_option('website_name');?>" class="regular-text">
    <p class="description"><?php _e('网站名称<strong>不影响</strong>任何认证过程，仅仅是为了方便辨认。', 'wwa');?></p>
</td>
</tr>
  <tr>
<th scope="row"><label for="website_domain"><?php _e('网站域名', 'wwa');?></lable></th>
<td>
    <input required name="website_domain" type="text" id="website_domain" value="<?php echo wwa_get_option('website_domain');?>" class="regular-text">
    <p class="description"><?php _e('<strong>必须</strong>与当前域名完全一致或为当前域名的子集。', 'wwa');?></p>
</td>
</tr>
</table><?php submit_button(); ?></form>
<?php }?>
<br>
<h2><?php _e('绑定认证器', 'wwa');?></h2>
<p class="description"><?php _e('你将为当前登录的账户添加一个认证器。同一个账户可以绑定多个不同的验证器。<br>如果需要为其他用户绑定认证器，请使用其他账户登录。', 'wwa');?></p>
<table class="form-table">
<tr>
<th scope="row"><label for="authenticator_type"><?php _e('认证器类型', 'wwa');?></label></th>
<td>
<select name="authenticator_type" id="authenticator_type">
    <option value="none" id="type-none" class="sub-type"><?php _e('任意类型', 'wwa');?></option>
    <option value="platform" id="type-platform" class="sub-type"><?php _e('限定内置认证器（如指纹传感器）', 'wwa');?></option>
    <option value="cross-platform" id="type-cross-platform" class="sub-type"><?php _e('限定外部认证器（如 USB Key）', 'wwa');?></option>
</select>
<p class="description"><?php _e('如果限定了认证器类型，浏览器将只会要求你提供指定类型的认证器。<br>无论你选择何种类型，登录时你只能使用绑定认证器时使用的同一个认证器。', 'wwa');?></p>
</td>
</tr>
<tr>
<th scope="row"><label for="authenticator_name"><?php _e('认证器名称', 'wwa');?></lable></th>
<td>
    <input required name="authenticator_name" type="text" id="authenticator_name" class="regular-text">
    <p class="description"><?php _e('给认证器设置一个便于辨认的名字，<strong>不影响</strong>认证过程。', 'wwa');?></p>
</td>
</tr>
</table>
<p class="submit"><button id="bind" class="button button-primary"><?php _e('开始绑定', 'wwa');?></button>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="show-progress"></span></p>
<h2><?php _e('当前账户已绑定的认证器', 'wwa');?></h2>
<table class="wp-list-table widefat fixed striped">
    <thead>
        <tr>
            <th><?php _e('认证器名称', 'wwa');?></th>
            <th><?php _e('认证器类型', 'wwa');?></th>
            <th><?php _e('添加时间', 'wwa');?></th>
            <th><?php _e('操作', 'wwa');?></th>
        </tr>
    </thead>
    <tbody id="authenticator-list">
        <tr>
            <td><?php _e('加载中...', 'wwa');?></td>
            <td></td>
            <td></td>
            <td></td>
        </tr>
    </tbody>
    <tfoot>
        <tr>
            <th><?php _e('认证器名称', 'wwa');?></th>
            <th><?php _e('认证器类型', 'wwa');?></th>
            <th><?php _e('添加时间', 'wwa');?></th>
            <th><?php _e('操作', 'wwa');?></th>
      </tr>
    </tfoot>
</table>
<br>
<h2><?php _e('测试绑定', 'wwa');?></h2>
<p class="description"><?php _e('点击测试按钮，你可以使用已绑定的认证器进行测试登录。', 'wwa');?></p>
<p class="submit"><button id="test" class="button button-primary"><?php _e('测试', 'wwa');?></button>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="show-test"></span></p>
</div>