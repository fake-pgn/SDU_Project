import numpy as np
from blind_watermark import WaterMark
from blind_watermark import att
from blind_watermark.recover import estimate_crop_parameters, recover_crop
import cv2
import os
import matplotlib.pyplot as plt
from blind_watermark import bw_notes
import sys

if sys.platform == 'win32':
    plt.rcParams['font.sans-serif'] = ['SimHei']
    plt.rcParams['axes.unicode_minus'] = False
else:
    plt.rcParams['font.sans-serif'] = ['DejaVu Sans']
bw_notes.close()
os.chdir(os.path.dirname(__file__))



def create_text_image(text, size=(200, 200)):
    img = np.zeros((*size, 3), dtype=np.uint8)
    font = cv2.FONT_HERSHEY_SIMPLEX
    text_size = cv2.getTextSize(text, font, 1, 2)[0]
    text_x = (size[1] - text_size[0]) // 2
    text_y = (size[0] + text_size[1]) // 2
    cv2.putText(img, text, (text_x, text_y), font, 1, (255, 255, 255), 2)
    return img


def test_robustness(attack_func, recover_func, attack_params, recover_params,
                    case_name, embedded_path, len_wm, original_wm, ori_img_shape=None):
    attack_path = f'output/{case_name}_attack.png'
    recover_path = f'output/{case_name}_recover.png'

    attack_func(input_filename=embedded_path, output_file_name=attack_path, **attack_params)

    if recover_func:
        if 'image_o_shape' in recover_func.__code__.co_varnames and ori_img_shape is not None:
            recover_params['image_o_shape'] = ori_img_shape

        if recover_func == att.rot_att:
            recover_func(input_filename=attack_path, output_file_name=recover_path, **recover_params)
        elif recover_func == recover_crop:
            recover_func(template_file=attack_path, output_file_name=recover_path, **recover_params)
        else:
            recover_func(input_filename=attack_path, output_file_name=recover_path, **recover_params)

        extract_path = recover_path
    else:
        extract_path = attack_path

    bwm1 = WaterMark(password_wm=1, password_img=1)
    wm_extract = bwm1.extract(extract_path, wm_shape=len_wm, mode='str')

    watermarked_img = cv2.imread(embedded_path)
    if watermarked_img is not None:
        watermarked_img = watermarked_img[:, :, ::-1]

    attacked_img = cv2.imread(attack_path)
    if attacked_img is not None:
        attacked_img = attacked_img[:, :, ::-1]

    original_wm_img = create_text_image(original_wm)
    extracted_wm_img = create_text_image(wm_extract)

    plt.figure(figsize=(15, 5))

    plt.subplot(141)
    if watermarked_img is not None:
        plt.imshow(watermarked_img)
    plt.title("原始含水印图像")
    plt.axis('off')

    plt.subplot(142)
    if attacked_img is not None:
        plt.imshow(attacked_img)
    plt.title(f"攻击类型：{case_name}")
    plt.axis('off')

    plt.subplot(143)
    plt.imshow(extracted_wm_img)
    plt.title("提取的水印")
    plt.axis('off')

    plt.subplot(144)
    plt.imshow(original_wm_img)
    plt.title("原始水印")
    plt.axis('off')

    plt.suptitle(f"{case_name}", fontsize=14)
    plt.tight_layout()
    plt.show()

    return wm_extract


# 新增对比度+伽马攻击函数
def contrast_gamma_att(input_filename, output_file_name, alpha=1.2, gamma=1.1):
    img = cv2.imread(input_filename)
    if img is None:
        raise FileNotFoundError(f"输入文件不存在: {input_filename}")
    img_contrast = cv2.convertScaleAbs(img, alpha=alpha, beta=0)
    invGamma = 1.0 / gamma
    table = np.array([((i / 255.0) ** invGamma) * 255 for i in np.arange(256)]).astype("uint8")
    img_gamma = cv2.LUT(img_contrast, table)
    cv2.imwrite(output_file_name, img_gamma)


# ======= 主程序 =======

bwm = WaterMark(password_img=1, password_wm=1)
bwm.read_img('lena.jpg')
wm_str = 'zhc'
bwm.read_wm(wm_str, mode='str')
bwm.embed('output/embedded.png')

len_wm = len(bwm.wm_bit)
ori_img_shape = cv2.imread('lena.jpg').shape[:2]
h, w = ori_img_shape

print(f'水印比特长度: {len_wm}')

bwm1 = WaterMark(password_img=1, password_wm=1)
wm_extract = bwm1.extract('output/embedded.png', wm_shape=len_wm, mode='str')
print(f"无攻击测试提取结果: {wm_extract}")

original_img = cv2.imread('lena.jpg')
if original_img is not None:
    original_img = original_img[:, :, ::-1]

watermarked_img = cv2.imread('output/embedded.png')
if watermarked_img is not None:
    watermarked_img = watermarked_img[:, :, ::-1]

plt.figure(figsize=(10, 5))
plt.subplot(131)
if original_img is not None:
    plt.imshow(original_img)
plt.title("原始图像")
plt.axis('off')

plt.subplot(132)
if watermarked_img is not None:
    plt.imshow(watermarked_img)
plt.title("含水印图像")
plt.axis('off')

plt.subplot(133)
plt.imshow(create_text_image(wm_extract, (100, 300)))
plt.title("提取的水印")
plt.axis('off')

plt.suptitle(f"无攻击测试", fontsize=14)
plt.tight_layout()
plt.show()

# 截图攻击1：已知参数
test_robustness(
    attack_func=att.cut_att3,
    recover_func=recover_crop,
    attack_params={
        'loc': (int(w * 0.1), int(h * 0.1), int(w * 0.5), int(h * 0.5)),
        'scale': 0.7
    },
    recover_params={
        'loc': (int(w * 0.1), int(h * 0.1), int(w * 0.5), int(h * 0.5))
    },
    case_name="截图攻击1(已知参数)",
    embedded_path='output/embedded.png',
    len_wm=len_wm,
    original_wm=wm_str,
    ori_img_shape=ori_img_shape
)

# 截图攻击2：未知参数
loc_r = ((0.1, 0.1), (0.7, 0.6))
scale = 0.7
x1, y1, x2, y2 = int(w * loc_r[0][0]), int(h * loc_r[0][1]), int(w * loc_r[1][0]), int(h * loc_r[1][1])

# 执行攻击
att.cut_att3(input_filename='output/embedded.png',
             output_file_name='output/screenshot_attack2.png',
             loc=(x1, y1, x2, y2), scale=scale)

# 估计裁剪参数
(x1_est, y1_est, x2_est, y2_est), image_o_shape, score, scale_infer = estimate_crop_parameters(
    original_file='output/embedded.png',
    template_file='output/screenshot_attack2.png',
    scale=(0.5, 2),
    search_num=200)

print(f'实际裁剪参数: x1={x1}, y1={y1}, x2={x2}, y2={y2}')
print(
    f'估计裁剪参数: x1={x1_est}, y1={y1_est}, x2={x2_est}, y2={y2_est}, 缩放比例={scale_infer:.2f}, 匹配分数={score:.2f}')

# 恢复裁剪
recover_crop(template_file='output/screenshot_attack2.png',
             output_file_name='output/screenshot_attack2_recover.png',
             loc=(x1_est, y1_est, x2_est, y2_est),
             image_o_shape=image_o_shape)

# 提取水印并可视化
bwm1 = WaterMark(password_wm=1, password_img=1)
wm_extract = bwm1.extract('output/screenshot_attack2_recover.png', wm_shape=len_wm, mode='str')
print(f"截图攻击2(未知参数)提取结果: {wm_extract}")

watermarked_img = cv2.imread('output/embedded.png')
if watermarked_img is not None:
    watermarked_img = watermarked_img[:, :, ::-1]

attacked_img = cv2.imread('output/screenshot_attack2.png')
if attacked_img is not None:
    attacked_img = attacked_img[:, :, ::-1]

recovered_img = cv2.imread('output/screenshot_attack2_recover.png')
if recovered_img is not None:
    recovered_img = recovered_img[:, :, ::-1]

# 可视化
plt.figure(figsize=(15, 5))
plt.subplot(141)
if watermarked_img is not None:
    plt.imshow(watermarked_img)
plt.title("原始含水印图像")
plt.axis('off')

plt.subplot(142)
if attacked_img is not None:
    plt.imshow(attacked_img)
plt.title("攻击类型：截图攻击2(未知参数)")
plt.axis('off')

plt.subplot(143)
plt.imshow(create_text_image(wm_extract))
plt.title("提取的水印")
plt.axis('off')

plt.subplot(144)
plt.imshow(create_text_image(wm_str))
plt.title("原始水印")
plt.axis('off')

plt.suptitle("截图攻击2(未知参数)", fontsize=14)
plt.tight_layout()
plt.show()

# 其他攻击测试
test_cases = [
    {
        "name": "椒盐噪声攻击",
        "attack_func": att.salt_pepper_att,
        "recover_func": None,
        "attack_params": {"ratio": 0.05},
        "recover_params": {}
    },
    {
        "name": "旋转攻击",
        "attack_func": att.rot_att,
        "recover_func": att.rot_att,
        "attack_params": {"angle": 60},
        "recover_params": {"angle": -60}
    },
    {
        "name": "遮挡攻击",
        "attack_func": att.shelter_att,
        "recover_func": None,
        "attack_params": {"ratio": 0.1, "n": 60},
        "recover_params": {}
    },
    {
        "name": "缩放攻击",
        "attack_func": att.resize_att,
        "recover_func": att.resize_att,
        "attack_params": {"out_shape": (400, 300)},
        "recover_params": {"out_shape": ori_img_shape[::-1]}
    },
    {
        "name": "亮度攻击",
        "attack_func": att.bright_att,
        "recover_func": att.bright_att,
        "attack_params": {"ratio": 0.9},
        "recover_params": {"ratio": 1.1}
    },
    {
        "name": "对比度攻击",
        "attack_func": contrast_gamma_att,
        "recover_func": None,
        "attack_params": {"alpha": 1.2, "gamma": 1.1},
        "recover_params": {}
    }
]

for case in test_cases:
    wm_extract = test_robustness(
        attack_func=case["attack_func"],
        recover_func=case["recover_func"],
        attack_params=case["attack_params"],
        recover_params=case["recover_params"],
        case_name=case["name"],
        embedded_path='output/embedded.png',
        len_wm=len_wm,
        original_wm=wm_str,
        ori_img_shape=ori_img_shape
    )

    print(f"{case['name']}测试结果: {wm_extract}")
