import { TextControl, CheckboxControl } from "@wordpress/components";

const { __ } = wp.i18n;
const { registerBlockType } = wp.blocks;

registerBlockType("wp-webauthn/login", {
    title: __("WebAuthn Login Form", "wp-webauthn"),
    icon: "admin-network",
    category: "widgets",
    keywords: ["WebAuthn", __("Login Form", "wp-webauthn")],
    attributes: {
        traditional: {
            type: "boolean",
            default: true
        },
        username: {
            type: "string",
            default: ''
        },
        autoHide: {
            type: "boolean",
            default: true
        },
        to: {
            type: "string",
            default: ''
        }
    },
    edit: ({ attributes, setAttributes, className }) => {
        return (
            <div
                className={className}
                style={{
                    padding: "20px",
                    boxSizing: "border-box",
                    backgroundColor: "#F4F4F4",
                    borderRadius: "3px"
                }}
            >
                <span style={{
                    fontSize: "15px",
                    marginBottom: "20px",
                    opacity: ".5"
                }}>
                    {__("WebAuthn Login Form", "wp-webauthn")}
                </span>
                <TextControl
                    label={__("Default username", "wp-webauthn")}
                    value={attributes.username}
                    onChange={val => {
                        setAttributes({ username: val });
                    }}
                />
                <TextControl
                    label={__("Redirect to", "wp-webauthn")}
                    value={attributes.to}
                    onChange={val => {
                        setAttributes({ to: val });
                    }}
                />
                <CheckboxControl
                    label={__("Show password form as well", "wp-webauthn")}
                    checked={attributes.traditional}
                    onChange={val => {
                        setAttributes({ traditional: val });
                    }}
                />
                <CheckboxControl
                    label={__("Hide for logged-in users", "wp-webauthn")}
                    checked={attributes.autoHide}
                    onChange={val => {
                        setAttributes({ autoHide: val });
                    }}
                />
            </div>
        );
    },
    save: ({ attributes }) => {
        return `[wwa_login_form traditional="${attributes.traditional}" auto_hide="${attributes.autoHide}"${attributes.username ? ` username="${attributes.username}"` : ''}${attributes.to ? ` to="${attributes.to}"` : ''}]`;
    }
});

registerBlockType("wp-webauthn/register", {
    title: __("WebAuthn Register Form", "wp-webauthn"),
    icon: "plus-alt",
    category: "widgets",
    keywords: ["WebAuthn", __("Register Form", "wp-webauthn")],
    attributes: {
        display: {
            type: "boolean",
            default: true
        }
    },
    edit: ({ attributes, setAttributes, className }) => {
        return (
            <div
                className={className}
                style={{
                    padding: "20px",
                    boxSizing: "border-box",
                    backgroundColor: "#F4F4F4",
                    borderRadius: "3px"
                }}
            >
                <span style={{
                    fontSize: "15px",
                    marginBottom: "20px",
                    opacity: ".5"
                }}>
                    {__("WebAuthn Register Form", "wp-webauthn")}
                </span>
                <div
                    className={className}
                    style={{
                        height: "150px",
                        display: "flex",
                        justifyContent: "center",
                        alignItems: "center"
                    }}
                >
                    <CheckboxControl
                        label={__("Show a message for users who doesn't logged-in", "wp-webauthn")}
                        checked={attributes.display}
                        onChange={val => {
                            setAttributes({ display: val });
                        }}
                    />
                </div>
            </div>
        );
    },
    save: ({ attributes }) => {
        return `[wwa_register_form display="${attributes.display}"]`;
    }
});


registerBlockType("wp-webauthn/verify", {
    title: __("WebAuthn Verify Buttons", "wp-webauthn"),
    icon: "sos",
    category: "widgets",
    keywords: ["WebAuthn", __("Verify Buttons", "wp-webauthn")],
    attributes: {
        display: {
            type: "boolean",
            default: true
        }
    },
    edit: ({ attributes, setAttributes, className }) => {
        return (
            <div
                className={className}
                style={{
                    padding: "20px",
                    boxSizing: "border-box",
                    backgroundColor: "#F4F4F4",
                    borderRadius: "3px"
                }}
            >
                <span style={{
                    fontSize: "15px",
                    marginBottom: "20px",
                    opacity: ".5"
                }}>
                    {__("WebAuthn Verify Buttons", "wp-webauthn")}
                </span>
                <div
                    className={className}
                    style={{
                        height: "50px",
                        display: "flex",
                        justifyContent: "center",
                        alignItems: "center"
                    }}
                >
                    <CheckboxControl
                        label={__("Show a message for users who doesn't logged-in", "wp-webauthn")}
                        checked={attributes.display}
                        onChange={val => {
                            setAttributes({ display: val });
                        }}
                    />
                </div>
            </div>
        );
    },
    save: ({ attributes }) => {
        return `[wwa_verify_button display="${attributes.display}"]`;
    }
});

registerBlockType("wp-webauthn/list", {
    title: __("WebAuthn Authenticator List", "wp-webauthn"),
    icon: "menu",
    category: "widgets",
    keywords: ["WebAuthn", __("Authenticator List", "wp-webauthn")],
    attributes: {
        display: {
            type: "boolean",
            default: true
        }
    },
    edit: ({ attributes, setAttributes, className }) => {
        return (
            <div
                className={className}
                style={{
                    padding: "20px",
                    boxSizing: "border-box",
                    backgroundColor: "#F4F4F4",
                    borderRadius: "3px"
                }}
            >
                <span style={{
                    fontSize: "15px",
                    marginBottom: "20px",
                    opacity: ".5"
                }}>
                    {__("WebAuthn Authenticator List", "wp-webauthn")}
                </span>
                <div
                    className={className}
                    style={{
                        height: "150px",
                        display: "flex",
                        justifyContent: "center",
                        alignItems: "center"
                    }}
                >
                    <CheckboxControl
                        label={__("Show a message for users who doesn't logged-in", "wp-webauthn")}
                        checked={attributes.display}
                        onChange={val => {
                            setAttributes({ display: val });
                        }}
                    />
                </div>
            </div>
        );
    },
    save: ({ attributes }) => {
        return `[wwa_list display="${attributes.display}"]`;
    }
});
